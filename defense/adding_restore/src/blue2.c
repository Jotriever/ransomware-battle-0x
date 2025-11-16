#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>     // realpath 함수 사용을 위해 추가
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/types.h>
#include "analyzer.h" // 스코어 계산하는 함수
#include "extension_checker.h" // 확장자 검사 모듈
#include "file_size_tracker.h" // 파일 크기 추적 모듈
#include "logger.h" // 로깅 모듈
#include "pattern_detector.h" // 구간별 엔트로피 패턴 감지 모듈
#include "whitelist.h" // 화이트리스트 관리 모듈
#include "dummy_file.h" // 더미 파일 관리 모듈
#include "process_tracker.h" // PID 추적 및 Malice Score 관리 모듈
#include "restore.h" //[RESTORE] restore함수
#define KILL_THRESHOLD 80    // Malice Score 강제 종료 임계값 ((임시))

//이은지 추가 부분 : [RESTORE] 검색

static int base_fd = -1;

static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/')
            path++;
        strncpy(relpath, path, PATH_MAX);
    }
}

// getattr 함수 구현
static int myfs_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi) {
    (void) fi;
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = fstatat(base_fd, relpath, stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;
    
    // 파일 크기 추적: 일반 파일인 경우 원본 크기 저장 (아직 추적되지 않은 경우)
    if (S_ISREG(stbuf->st_mode)) {
        FileSizeEntry *entry = find_or_create_file_size_entry(path);
        if (entry != NULL && entry->is_tracked == 0) {
            entry->original_size = stbuf->st_size;
            entry->is_tracked = 1;
        }
    }
    
    // 화이트리스트에 없는 파일의 실행 권한 제거
    if (S_ISREG(stbuf->st_mode) && (stbuf->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
        // 화이트리스트에 없는 파일이면 실행 권한 제거
        if (!is_writable_whitelisted(path)) {
            stbuf->st_mode &= ~(S_IXUSR | S_IXGRP | S_IXOTH);
        }
    }

    return 0;
}

// readdir 함수 구현
static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags) {
    DIR *dp;
    struct dirent *de;
    int fd;

    (void) offset;
    (void) fi;
    (void) flags;

    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    fd = openat(base_fd, relpath, O_RDONLY | O_DIRECTORY);
    if (fd == -1)
        return -errno;

    dp = fdopendir(fd);
    if (dp == NULL) {
        close(fd);
        return -errno;
    }

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0))
            break;
    }

    closedir(dp);
    return 0;
}

// open 함수 구현
static int myfs_open(const char *path, struct fuse_file_info *fi) {
    // 더미 파일 접근 체크 (읽기/쓰기 모두)
    if (is_dummy_file(path)) {
        block_process_on_dummy_access(path);
        return -EACCES; // 접근 거부
    }
    
    // 화이트리스트 파일은 모든 작업 허용, 그 외 파일도 읽기/쓰기 허용 (실행만 차단)

    // [restore] O_TRUNC 플래그 제거: 파일 내용이 즉시 지워지는 것을 방지
    fi->flags &= ~O_TRUNC; // <- [restore]추가

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = openat(base_fd, relpath, fi->flags);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

// create 함수 구현
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    // 더미 파일 생성 시도 체크
    if (is_dummy_file(path)) {
        block_process_on_dummy_access(path);
        return -EACCES;
    }
    
    // 화이트리스트 파일이 아닌 경우에도 생성은 허용 (가용성)
    // 쓰기/삭제는 화이트리스트 파일만 허용

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = openat(base_fd, relpath, fi->flags | O_CREAT, mode);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

// read 함수 구현
static int myfs_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
    // 더미 파일 읽기 체크
    if (is_dummy_file(path)) {
        block_process_on_dummy_access(path);
        return -EACCES;
    }
    
    int res;

    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

// write 함수 구현
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    // 더미 파일 쓰기 체크
    if (is_dummy_file(path)) {
        block_process_on_dummy_access(path);
        return -EACCES;
    }
    // [RESTORE] 백업 함수 호출(쓰기 직전의 원본 확보)
    restore_backup_on_write(path, base_fd);

    // [restore] Truncation 및 fsync 실행 (CoW 직후 원본 지우고 동기화)
    if (fi->flags & O_TRUNC) {
        if (ftruncate(fi->fh, 0) == -1) {
            fprintf(stderr, "RESTORE: Truncate failed after CoW prep.\n");
        }
        // fsync는 O_TRUNC 다음에 호출되어야 안전함
        if (fsync(fi->fh) == -1) {
            fprintf(stderr, "RESTORE: Warning: fsync failed during CoW prep.\n");
        }
        fi->flags &= ~O_TRUNC; // 플래그를 제거하여 다음 write에 영향 없도록
    }
    
    // 화이트리스트 파일은 모든 작업 허용, 그 외 파일도 쓰기 허용 (실행만 차단)
    
    // PID 획득
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;
    
    // 1. 랜섬웨어 확장자 감지
    if (is_ransomware_extension(path)) {
        log_kill_ransomware_extension(current_pid, path, "파일 쓰기 (WRITE)", NULL);
        
        // 프로세스 강제 종료
        if (kill(current_pid, SIGKILL) == -1) {
            log_message("❌ 킬 명령어 실패: %s\n", strerror(errno));
        } else {
            log_message("✅ 프로세스 PID %d 강제 종료 완료\n", current_pid);
        }
        
        return -EIO;
    }
    
    // Score 계산 및 갱신 -> (수정사항: get_score() 함수 사용함
    int added_score = get_score("WRITE", buf, size);

    update_malice_score(current_pid, added_score);
    
    
    // 임계값 확인 후 강제 종료 조치
    if (get_malice_score(current_pid) >= KILL_THRESHOLD) {
        int current_score = get_malice_score(current_pid);
        log_kill_malice_score(current_pid, current_score, KILL_THRESHOLD, path, "파일 쓰기 (WRITE)", NULL);
        
        //[RESTORE] 복구 함수 호출(KILL 됐을 때 원본 덮어쓰기)
        restore_backup_file(path, base_fd);

        // 강제 종료 실행
        if (kill(current_pid, SIGKILL) == -1) {
            log_message("❌ 킬 명령어 실패: %s\n", strerror(errno));
        } else {
            log_message("✅ 프로세스 PID %d 강제 종료 완료\n", current_pid);
        }

        // 쓰기 연산 차단 및 에러 반환
        return -EIO; 
    }

    // 정상 연산 
    int res;
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) {
        res = -errno;
    }
    
    // 2. 파일 크기 변화 분석 (쓰기 후 현재 파일 크기 확인)
    if (res > 0) {
        struct stat st;
        char relpath[PATH_MAX];
        get_relative_path(path, relpath);
        
        if (fstatat(base_fd, relpath, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            check_file_size_change(path, st.st_size, current_pid);
            
            // 3. 구간별 엔트로피 패턴 감지 (4번 이상 반복 시 강제 종료)
            if (detect_entropy_pattern(path, base_fd, current_pid)) {
                // 패턴이 4번 이상 반복되면 프로세스 강제 종료
                if (kill(current_pid, SIGKILL) == -1) {
                    log_message("❌ 킬 명령어 실패: %s\n", strerror(errno));
                } else {
                    log_message("✅ 프로세스 PID %d 강제 종료 완료\n", current_pid);
                }
                return -EIO;
            }
        }
    }
    
    return res;
}

// release 함수 구현
static int myfs_release(const char *path, struct fuse_file_info *fi) {
    close(fi->fh);
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;

    reset_malice_score(current_pid); //파일 닫으면 해당 p의 score초기화
    return 0;
}

// unlink 함수 구현 (파일 삭제)
static int myfs_unlink(const char *path) {
    // 더미 파일 삭제 시도 체크
    if (is_dummy_file(path)) {
        block_process_on_dummy_access(path);
        return -EACCES;
    }
    
    // 화이트리스트 파일은 모든 작업 허용, 그 외 파일도 삭제 허용 (실행만 차단)
    
    struct fuse_context *context = fuse_get_context(); //(새로추가) -> PID 획득
    pid_t current_pid = context->pid;
    
    int added_score = get_score("UNLINK", NULL, 0); //(새로추가) -> score 계산 (buf/size 가 없으므로 NULL,0 을 전달)
    update_malice_score(current_pid, added_score); //(새로추가) -> 추가하기
   
    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {//(if 문 전체 새로 추가)
        int current_score = get_malice_score(current_pid);
        log_kill_malice_score(current_pid, current_score, KILL_THRESHOLD, path, "파일 삭제 (UNLINK)", NULL);
        
        //[RESTORE] 복구 함수 호출(KILL됐을 때 원본 복구)
        restore_backup_file(path, base_fd);

        if(kill(current_pid,SIGKILL) == -1){
            log_message("❌ 킬 명령어 실패: %s\n", strerror(errno));
        } else {
            log_message("✅ 프로세스 PID %d 강제 종료 완료\n", current_pid);
        }
        return -EIO;
    }
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = unlinkat(base_fd, relpath, 0);
    if (res == -1)
        return -errno;

    return 0;
}

// mkdir 함수 구현 (디렉터리 생성)
static int myfs_mkdir(const char *path, mode_t mode) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = mkdirat(base_fd, relpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

// rmdir 함수 구현 (디렉터리 삭제)
static int myfs_rmdir(const char *path) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = unlinkat(base_fd, relpath, AT_REMOVEDIR);
    if (res == -1)
        return -errno;

    return 0;
}

// rename 함수 구현 (파일/디렉터리 이름 변경)
static int myfs_rename(const char *from, const char *to, unsigned int flags) {
    // 더미 파일 관련 체크
    if (is_dummy_file(from) || is_dummy_file(to)) {
        block_process_on_dummy_access(is_dummy_file(from) ? from : to);
        return -EACCES;
    }
    
    // 화이트리스트 파일은 모든 작업 허용, 그 외 파일도 이름 변경 허용 (실행만 차단)
    
    struct fuse_context *context = fuse_get_context(); //(새로추가) -> PID 획득
    pid_t current_pid = context->pid;

    // 1. 랜섬웨어 확장자 감지 (이름 변경 후 확장자 확인)
    if (is_ransomware_extension(to)) {
        log_kill_ransomware_extension(current_pid, to, "파일 이름 변경 (RENAME)", from);
        
        // 프로세스 강제 종료
        if (kill(current_pid, SIGKILL) == -1) {
            log_message("❌ 킬 명령어 실패: %s\n", strerror(errno));
        } else {
            log_message("✅ 프로세스 PID %d 강제 종료 완료\n", current_pid);
        }
        
        return -EIO;
    }

    int added_score = get_score("RENAME", NULL, 0); //(새로추가) -> score 계산 (buf/size 가 없으므로 NULL,0 을 전달)
    update_malice_score(current_pid, added_score); //(새로추가) -> 추가하기

    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {//(if 문 전체 새로 추가)
        int current_score = get_malice_score(current_pid);
        log_kill_malice_score(current_pid, current_score, KILL_THRESHOLD, to, "파일 이름 변경 (RENAME)", from);
        
        //[RESTORE] 복구 함수 호출 ('from' 경로에 원본을 복원)
            restore_backup_file(from, base_fd);

        if(kill(current_pid,SIGKILL) == -1){
            log_message("❌ 킬 명령어 실패: %s\n", strerror(errno));
        } else {
            log_message("✅ 프로세스 PID %d 강제 종료 완료\n", current_pid);
        }
        return -EIO;
    }
    int res;
    char relfrom[PATH_MAX];
    char relto[PATH_MAX];
    get_relative_path(from, relfrom);
    get_relative_path(to, relto);

    if (flags)
        return -EINVAL;

    res = renameat(base_fd, relfrom, base_fd, relto);
    if (res == -1)
        return -errno;

    // 파일 크기 추적 엔트리 경로 업데이트 (rename 시)
    update_file_size_entry_path(from, to);

    return 0;
}

// utimens 함수 구현
static int myfs_utimens(const char *path, const struct timespec tv[2],
                        struct fuse_file_info *fi) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    if (fi != NULL && fi->fh != 0) {
        // 파일 핸들이 있는 경우
        res = futimens(fi->fh, tv);
    } else {
        // 파일 핸들이 없는 경우
        res = utimensat(base_fd, relpath, tv, 0);
    }
    if (res == -1)
        return -errno;

    return 0;
}

// 파일시스템 연산자 구조체
static const struct fuse_operations myfs_oper = {
    .getattr    = myfs_getattr,
    .readdir    = myfs_readdir,
    .open       = myfs_open,
    .create     = myfs_create,
    .read       = myfs_read,
    .write      = myfs_write,
    .release    = myfs_release,
    .unlink     = myfs_unlink,
    .mkdir      = myfs_mkdir,
    .rmdir      = myfs_rmdir,
    .rename     = myfs_rename,
    .utimens    = myfs_utimens,  
};


int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mountpoint>\n", argv[0]);
        return -1;
    }

    // 마운트 포인트 경로 저장
    char *mountpoint = realpath(argv[argc - 1], NULL);
    if (mountpoint == NULL) {
        perror("realpath");
        return -1;
    }

    // 로거 초기화 (환경 변수로 로그 파일 경로 설정 가능)
    const char *log_file = getenv("DEFENSE_LOG_FILE");
    if (init_logger(log_file) != 0) {
        fprintf(stderr, "Warning: Logger initialization failed, continuing without file logging\n");
    }
    
    // 백엔드 경로는 고정: $HOME/workspace/target
    const char *home_dir = getenv("HOME");
    if (!home_dir) {
        fprintf(stderr, "Error: HOME environment variable not set.\n");
        close_logger();
        free(mountpoint);
        return -1;
    }
    
    char backend_path[PATH_MAX];
    char backend_path_resolved[PATH_MAX];
    snprintf(backend_path, PATH_MAX, "%s/workspace/target", home_dir);
    
    // 백엔드 경로를 절대 경로로 변환
    if (realpath(backend_path, backend_path_resolved) == NULL) {
        // 경로가 존재하지 않으면 원본 경로 사용
        strncpy(backend_path_resolved, backend_path, PATH_MAX - 1);
        backend_path_resolved[PATH_MAX - 1] = '\0';
    }

    // 백엔드 디렉터리 열기 (base_fd 획득)
    fprintf(stderr, "INFO: Protecting backend path: %s\n", backend_path_resolved);
    
    base_fd = open(backend_path_resolved, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
	perror("Error opening backend directory");
	close_logger();
	free(mountpoint);
	return -1;
    }

    // [RESTORE] 초기화(경로) 호출
    if (restore_init(home_dir, backend_path) != 0) {
        close(base_fd);
        return -1;
    }

    // 백엔드 디렉토리의 모든 파일을 화이트리스트에 자동 등록
    fprintf(stderr, "INFO: Scanning directory and building whitelist...\n");
    scan_directory_recursive(backend_path_resolved, ".");
    fprintf(stderr, "INFO: Whitelist initialized with %d files\n", get_whitelist_count());
    
    // 더미 파일(낚시 파일) 생성 및 등록
    fprintf(stderr, "INFO: Creating dummy files for ransomware detection...\n");
    const char *dummy_files[] = {
        "/dummy_secret.txt",
        "/important_data.txt",
        "/private_key.pem",
        "/backup.db",
        "/confidential.doc",
        NULL
    };
    
    for (int i = 0; dummy_files[i] != NULL; i++) {
        char dummy_full_path[PATH_MAX];
        char dummy_rel_path[PATH_MAX];
        
        // FUSE 경로를 상대 경로로 변환
        get_relative_path(dummy_files[i], dummy_rel_path);
        snprintf(dummy_full_path, PATH_MAX, "%s/%s", backend_path_resolved, dummy_rel_path);
        
        // 더미 파일 생성 (이미 존재하면 무시)
        int fd = openat(base_fd, dummy_rel_path, O_CREAT | O_WRONLY | O_EXCL, 0644);
        if (fd >= 0) {
            // 더미 파일에 가짜 내용 작성
            const char *dummy_content = "This is a dummy file for ransomware detection.\n";
            write(fd, dummy_content, strlen(dummy_content));
            close(fd);
            
            // 더미 파일 목록에 추가
            add_to_dummy_list(dummy_files[i]);
            fprintf(stderr, "INFO: Created dummy file: %s\n", dummy_files[i]);
        } else if (errno == EEXIST) {
            // 이미 존재하는 경우에도 더미 파일 목록에 추가
            add_to_dummy_list(dummy_files[i]);
            fprintf(stderr, "INFO: Dummy file already exists: %s\n", dummy_files[i]);
        }
    }
    fprintf(stderr, "INFO: Dummy file list initialized with %d files\n", get_dummy_file_count());

    // FUSE 파일시스템 실행
    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);

    // 정리
    free_whitelist();
    free_dummy_list();
    close(base_fd);
    close_logger(); // 로거 닫기
    free(mountpoint);
    return ret;
}

