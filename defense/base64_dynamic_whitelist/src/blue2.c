#define FUSE_USE_VERSION 35
#define MAX_TRACKED_PIDS 100
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
#define KILL_THRESHOLD 80    // Malice Score 강제 종료 임계값 ((임시))

static int base_fd = -1;

// 동적 화이트리스트 구조
#define MAX_WHITELIST_SIZE 10000  // 최대 화이트리스트 항목 수
static char **writable_whitelist = NULL;
static int whitelist_count = 0;
static int whitelist_capacity = 0;

// 더미 파일(낚시 파일) 목록 구조
static char **dummy_file_list = NULL;
static int dummy_file_count = 0;
static int dummy_file_capacity = 0;

// 화이트리스트에 경로 추가
static int add_to_whitelist(const char *path) {
    // 중복 체크
    for (int i = 0; i < whitelist_count; i++) {
        if (strcmp(path, writable_whitelist[i]) == 0) {
            return 0; // 이미 존재
        }
    }
    
    // 용량 부족 시 확장
    if (whitelist_count >= whitelist_capacity) {
        int new_capacity = whitelist_capacity == 0 ? 100 : whitelist_capacity * 2;
        if (new_capacity > MAX_WHITELIST_SIZE) {
            new_capacity = MAX_WHITELIST_SIZE;
        }
        
        char **new_list = realloc(writable_whitelist, new_capacity * sizeof(char*));
        if (new_list == NULL) {
            fprintf(stderr, "Error: Failed to allocate memory for whitelist\n");
            return -1;
        }
        writable_whitelist = new_list;
        whitelist_capacity = new_capacity;
    }
    
    // 경로 복사 및 추가
    writable_whitelist[whitelist_count] = strdup(path);
    if (writable_whitelist[whitelist_count] == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for whitelist entry\n");
        return -1;
    }
    whitelist_count++;
    
    return 0;
}

// 더미 파일 목록에 추가하는 함수
static int add_to_dummy_list(const char *path) {
    // 중복 체크
    for (int i = 0; i < dummy_file_count; i++) {
        if (strcmp(path, dummy_file_list[i]) == 0) {
            return 0; // 이미 존재
        }
    }
    
    // 용량 부족 시 확장
    if (dummy_file_count >= dummy_file_capacity) {
        int new_capacity = dummy_file_capacity == 0 ? 10 : dummy_file_capacity * 2;
        char **new_list = realloc(dummy_file_list, new_capacity * sizeof(char*));
        if (new_list == NULL) {
            fprintf(stderr, "Error: Failed to allocate memory for dummy file list\n");
            return -1;
        }
        dummy_file_list = new_list;
        dummy_file_capacity = new_capacity;
    }
    
    // 경로 복사 및 추가
    dummy_file_list[dummy_file_count] = strdup(path);
    if (dummy_file_list[dummy_file_count] == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for dummy file entry\n");
        return -1;
    }
    dummy_file_count++;
    
    return 0;
}

// 더미 파일인지 확인
static int is_dummy_file(const char *path) {
    for (int i = 0; i < dummy_file_count; i++) {
        if (strcmp(path, dummy_file_list[i]) == 0) {
            return 1; // 더미 파일
        }
    }
    return 0; // 더미 파일 아님
}

// 더미 파일 접근 시 프로세스 차단그러
static void block_process_on_dummy_access(const char *path) {
    struct fuse_context *context = fuse_get_context();
    if (context) {
        pid_t current_pid = context->pid;
        fprintf(stderr, "ALERT: Dummy file access detected! PID %d accessing %s - KILLING PROCESS\n", 
                current_pid, path);
        
        // 프로세스 강제 종료
        if (kill(current_pid, SIGKILL) == -1) {
            fprintf(stderr, "Kill command failed: %s\n", strerror(errno));
        }
    }
}

// 해당 파일이 화이트리스트에 등록되어 있는지 확인
static int is_writable_whitelisted(const char *path) {
    // 화이트리스트 배열에 등록된 파일만 허용
    for (int i = 0; i < whitelist_count; i++) {
        if (strcmp(path, writable_whitelist[i]) == 0) {
            return 1; // 화이트리스트에 등록된 파일 - 쓰기 허용
        }
    }
    return 0; // 화이트리스트에 없는 파일 - 쓰기 차단
}

// 화이트리스트 메모리 해제
static void free_whitelist(void) {
    if (writable_whitelist != NULL) {
        for (int i = 0; i < whitelist_count; i++) {
            free(writable_whitelist[i]);
        }
        free(writable_whitelist);
        writable_whitelist = NULL;
        whitelist_count = 0;
        whitelist_capacity = 0;
    }
    
    // 더미 파일 목록 메모리 해제
    if (dummy_file_list != NULL) {
        for (int i = 0; i < dummy_file_count; i++) {
            free(dummy_file_list[i]);
        }
        free(dummy_file_list);
        dummy_file_list = NULL;
        dummy_file_count = 0;
        dummy_file_capacity = 0;
    }
}

// PID별 Malice Score, 행동 정보 저장할 구조체
typedef struct {
    pid_t pid;             
    int malice_score;      
    time_t last_write_time; // 마지막 쓰기 연산 시간 
    char proc_name[32];  //  프로세스 이름 저장
} ProcessScore;

// 전역 Score 테이블
ProcessScore g_score_table[MAX_TRACKED_PIDS];
int g_process_count = 0; // 현재 추적 중인 프로세스 개수

// ProcessScore 엔트리를 찾거나 새로 생성해 포인터 반환
ProcessScore* find_or_create_score_entry(pid_t pid) {
    // 기존 엔트리 검색
    for (int i = 0; i < g_process_count; i++) {
        if (g_score_table[i].pid == pid) {
            // PID가 이미 존재하면 해당 엔트리 반환
            return &g_score_table[i];
	}
    }
    
    // 새 엔트리 생성
    if (g_process_count < MAX_TRACKED_PIDS) {
        ProcessScore *new_entry = &g_score_table[g_process_count];
        // 새로운 엔트리 초기화
        new_entry->pid = pid;
        new_entry->malice_score = 0;
        new_entry->last_write_time = time(NULL);
        g_process_count++; // 추적 중인 프로세스 수 증가
        
        return new_entry;
    }
    
    // 배열이 가득 찼을 때 
    fprintf(stderr, "오류: 최대 PID 추적 개수 초과!\n");
    return NULL;
}

// 특정 PID의 Malice Score 업데이트, 마지막 쓰기 시간 갱신
void update_malice_score(pid_t pid, int added_score) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    
    if (entry) {
        entry->malice_score += added_score;
        entry->last_write_time = time(NULL); 
    }
}

// 특정 PID의 Malice Score 반환
int get_malice_score(pid_t pid) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    if (entry) {
        return entry->malice_score;
    }
    return 0; // 엔트리 못 찾으면 0점 반환
}

// 프로세스 종료 시 Score 0으로 초기화
void reset_malice_score(pid_t pid) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    if (entry) {
        entry->malice_score = 0;
    }
}

static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/')
            path++;
        strncpy(relpath, path, PATH_MAX);
    }
}

// 재귀적으로 디렉토리를 스캔하여 모든 파일을 화이트리스트에 추가
static void scan_directory_recursive(const char *base_path, const char *relative_path) {
    char full_path[PATH_MAX];
    char fuse_path[PATH_MAX];
    struct stat st;
    DIR *dir;
    struct dirent *entry;
    
    // 전체 경로 구성
    if (strcmp(relative_path, ".") == 0) {
        snprintf(full_path, PATH_MAX, "%s", base_path);
        snprintf(fuse_path, PATH_MAX, "/");
    } else {
        snprintf(full_path, PATH_MAX, "%s/%s", base_path, relative_path);
        snprintf(fuse_path, PATH_MAX, "/%s", relative_path);
    }
    
    // 디렉토리 열기
    dir = opendir(full_path);
    if (dir == NULL) {
        return; // 권한 없음 등으로 열 수 없으면 무시
    }
    
    // 디렉토리 내 항목 순회
    while ((entry = readdir(dir)) != NULL) {
        // . 과 .. 건너뛰기
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char entry_full_path[PATH_MAX];
        char entry_relative_path[PATH_MAX];
        char entry_fuse_path[PATH_MAX];
        
        // 전체 경로 구성
        snprintf(entry_full_path, PATH_MAX, "%s/%s", full_path, entry->d_name);
        
        // 상대 경로 구성
        if (strcmp(relative_path, ".") == 0) {
            snprintf(entry_relative_path, PATH_MAX, "%s", entry->d_name);
        } else {
            snprintf(entry_relative_path, PATH_MAX, "%s/%s", relative_path, entry->d_name);
        }
        
        // FUSE 경로 구성 (화이트리스트에 추가할 경로)
        snprintf(entry_fuse_path, PATH_MAX, "/%s", entry_relative_path);
        
        // 파일 정보 가져오기
        if (stat(entry_full_path, &st) == -1) {
            continue; // stat 실패 시 건너뛰기
        }
        
        // 파일이면 화이트리스트에 추가
        if (S_ISREG(st.st_mode)) {
            add_to_whitelist(entry_fuse_path);
            fprintf(stderr, "INFO: Added to whitelist: %s\n", entry_fuse_path);
        }
        // 디렉토리면 재귀 호출
        else if (S_ISDIR(st.st_mode)) {
            scan_directory_recursive(base_path, entry_relative_path);
        }
    }
    
    closedir(dir);
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
    
    // 화이트리스트 파일은 모든 작업 허용, 그 외 파일도 쓰기 허용 (실행만 차단)
    
    // PID 획득
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;
    
    // Score 계산 및 갱신 -> (수정사항: get_score() 함수 사용함
    int added_score = get_score("WRITE", buf, size);

    update_malice_score(current_pid, added_score);
    
    
    // 임계값 확인 후 강제 종료 조치
    if (get_malice_score(current_pid) >= KILL_THRESHOLD) {
        fprintf(stderr, "Kill ! 'write' 임계값 초과! PID %d 강제 종료\n", current_pid);
        
        // 강제 종료 실행
        if (kill(current_pid, SIGKILL) == -1) {
            fprintf(stderr, "킬 명령어 실패: %s\n", strerror(errno));
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
	    fprintf(stderr, "Kill ! 'unlink' 임계값 초과! PID %d 강제종료\n", current_pid);
	    if(kill(current_pid,SIGKILL) == -1){
		    fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
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

    int added_score = get_score("RENAME", NULL, 0); //(새로추가) -> score 계산 (buf/size 가 없으므로 NULL,0 을 전달)
    update_malice_score(current_pid, added_score); //(새로추가) -> 추가하기

    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {//(if 문 전체 새로 추가)
            fprintf(stderr, "Kill ! 'rename' 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1){
                    fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
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

    // 백엔드 경로는 고정: $HOME/workspace/target
    const char *home_dir = getenv("HOME");
    if (!home_dir) {
        fprintf(stderr, "Error: HOME environment variable not set.\n");
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
	free(mountpoint);
	return -1;
    }

    // 백엔드 디렉토리의 모든 파일을 화이트리스트에 자동 등록
    fprintf(stderr, "INFO: Scanning directory and building whitelist...\n");
    scan_directory_recursive(backend_path_resolved, ".");
    fprintf(stderr, "INFO: Whitelist initialized with %d files\n", whitelist_count);
    
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
    fprintf(stderr, "INFO: Dummy file list initialized with %d files\n", dummy_file_count);

    // FUSE 파일시스템 실행
    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);

    // 정리
    free_whitelist();
    close(base_fd);
    free(mountpoint);
    return ret;
}

