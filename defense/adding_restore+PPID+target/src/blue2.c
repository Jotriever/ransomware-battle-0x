/* blue2.c (최종 수정본) */
#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>     
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
#include "analyzer.h"
#include "process_tracker.h" // PID 추적 및 Malice Score 관리 모듈
#include "whitelist.h" // 화이트리스트 관리 모듈
#include "restore.h" // 복구 모듈
#include "dummy_file.h" // 더미 파일 관리 모듈
#include "extension_checker.h" // 확장자 검사 모듈
#include "file_size_tracker.h" // 파일 크기 추적 모듈
#include "logger.h" // 로깅 모듈
#include "pattern_detector.h" // 패턴 감지 모듈
#define KILL_THRESHOLD 150 //malice_score 임계값 (넘으면 강제 종료됨)   

static int base_fd = -1;

// 블랙리스트 (임시로 유지 - 향후 별도 모듈로 분리 가능)
static const char *blacklist[] = { "/ransomware.exe", NULL };

static int is_blacklisted(const char *path) {
    for (int i = 0; blacklist[i] != NULL; i++) {
        if (strcmp(path, blacklist[i]) == 0) return 1;
    }
    return 0; 
}

static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/') {
            strncpy(relpath, path + 1, PATH_MAX - 1);
        } else {
            strncpy(relpath, path, PATH_MAX - 1);
        }
        relpath[PATH_MAX - 1] = '\0';
    }
}

// getattr
static int myfs_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi) {
    //(12일 과제)
    struct fuse_context *context = fuse_get_context();
    if (context == NULL) {
        return -EIO;
    }
    pid_t current_pid = context->pid;
    int added_score = get_score("GETATTR",NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    //PPID 점수 누적
    pid_t ppid = get_ppid_of(current_pid);
    update_group_score(ppid, added_score);

    // PID 점수 검사
    int pid_score = get_malice_score(current_pid);
    if (pid_score >= KILL_THRESHOLD) {

        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "GETATTR", NULL);
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        return -EIO;
    }

    // 그룹(PPID) 점수 검사 
    int group_score = get_group_score(ppid);
    if (group_score >= KILL_THRESHOLD) {
	
        log_message("그룹 임계치 초과: PPID=%d Score=%d (함수=GETATTR)\n", ppid, group_score);
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "GETATTR", NULL);
        // 동일한 PPID 가진 모든 child kill
        kill_all_children(ppid);
        // 부모 kill (공격자 bash 터미널 죽음)
        kill(ppid, SIGKILL);
        // 현재도 kill
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        
        reset_group_score(ppid);
        reset_malice_score(current_pid);
        return -EIO;
    }

    (void) fi;
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    res = fstatat(base_fd, relpath, stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1) return -errno;
    
    // 파일 크기 추적: 일반 파일인 경우 원본 크기 저장
    if (S_ISREG(stbuf->st_mode)) {
        FileSizeEntry *entry = find_or_create_file_size_entry(path);
        if (entry != NULL && entry->is_tracked == 0) {
            entry->original_size = stbuf->st_size;
            entry->is_tracked = 1;
        }
    }
    
    if ((stbuf->st_mode & S_IFREG) && (stbuf->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
        if (is_blacklisted(path)) {
            stbuf->st_mode &= ~(S_IXUSR | S_IXGRP | S_IXOTH);
        }
    }
    return 0;
}

// readdir
static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
    			enum fuse_readdir_flags flags) {
    //(12일 과제)
    struct fuse_context *context = fuse_get_context();
    if (context == NULL) {
        return -EIO;
    }
    pid_t current_pid = context->pid;
    int added_score = get_score("READDIR",NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    //PPID 점수 누적
    pid_t ppid = get_ppid_of(current_pid);
    update_group_score(ppid, added_score);

    // PID 점수 검사
    int pid_score = get_malice_score(current_pid);
    if (pid_score >= KILL_THRESHOLD) {
    	
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "READDIR", NULL);
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        return -EIO;
    }

    // 그룹(PPID) 점수 검사 
    int group_score = get_group_score(ppid);
    if (group_score >= KILL_THRESHOLD) {
        log_message("그룹 임계치 초과: PPID=%d Score=%d (함수=READDIR)\n", ppid, group_score);
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "READDIR", NULL);
        // 동일한 PPID 가진 모든 child kill
        kill_all_children(ppid);
        // 부모 kill (공격자 bash 터미널 죽음)
        kill(ppid, SIGKILL);
        // 현재도 kill
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        
        reset_group_score(ppid);
        reset_malice_score(current_pid);
        return -EIO;
    }
    
    DIR *dp;
    struct dirent *de;
    int fd;
    (void) offset; (void) fi; (void) flags;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    fd = openat(base_fd, relpath, O_RDONLY | O_DIRECTORY);
    if (fd == -1) return -errno;
    dp = fdopendir(fd);
    if (dp == NULL) { close(fd); return -errno; }
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0)) break;
    }
    closedir(dp);
    return 0;
}

// open
static int myfs_open(const char *path, struct fuse_file_info *fi) {
    // 더미 파일 체크
    if (is_dummy_file(path)) {
        block_process_on_dummy_access(path);
        return -EACCES;
    }
    
    // [restore] O_TRUNC 플래그 제거: 파일 내용이 즉시 지워지는 것을 방지
    fi->flags &= ~O_TRUNC; // <- [restore]추가
    
    //(12일 과제)
    struct fuse_context *context = fuse_get_context();
    if (context == NULL) {
        return -EIO;
    }
    pid_t current_pid = context->pid;
    int added_score = get_score("OPEN",NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    //PPID 점수 누적
    pid_t ppid = get_ppid_of(current_pid);
    update_group_score(ppid, added_score);

    // PID 점수 검사
    int pid_score = get_malice_score(current_pid);
    if (pid_score >= KILL_THRESHOLD) {
  
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "OPEN", NULL);
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        return -EIO;
    }

    // 그룹(PPID) 점수 검사 
    int group_score = get_group_score(ppid);
    if (group_score >= KILL_THRESHOLD) {
    	
        log_message("그룹 임계치 초과: PPID=%d Score=%d (함수=OPEN)\n", ppid, group_score);
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "OPEN", NULL);
        // 동일한 PPID 가진 모든 child kill
        kill_all_children(ppid);
        // 부모 kill (공격자 bash 터미널 죽음)
        kill(ppid, SIGKILL);
        // 현재도 kill
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        
        reset_group_score(ppid);
        reset_malice_score(current_pid);
        return -EIO;
    }

    if ((fi->flags & O_WRONLY) || (fi->flags & O_RDWR)) {
        if (!is_writable_whitelisted(path)) return -EACCES; 
    }
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    res = openat(base_fd, relpath, fi->flags);
    if (res == -1) return -errno;
    fi->fh = res;
    return 0;
}

// create
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    // 랜섬웨어 확장자 체크
    if (is_ransomware_extension(path)) {
        struct fuse_context *context = fuse_get_context();
        pid_t current_pid = context ? context->pid : 0;
        log_kill_ransomware_extension(current_pid, path, "CREATE", NULL);
        if (context && kill(current_pid, SIGKILL) == -1) {
            log_message("킬명령어 실패: %s\n", strerror(errno));
        }
        return -EACCES;
    }
    
    //(12일 과제)
    struct fuse_context *context = fuse_get_context();
    if (context == NULL) {
        return -EIO;
    }
    pid_t current_pid = context->pid;
    int added_score = get_score("CREATE", NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    //PPID 점수 누적
    pid_t ppid = get_ppid_of(current_pid);
    update_group_score(ppid, added_score);

    // PID 점수 검사
    int pid_score = get_malice_score(current_pid);
    if (pid_score >= KILL_THRESHOLD) {
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "CREATE", NULL);
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        return -EIO;
    }

    // 그룹(PPID) 점수 검사 
    int group_score = get_group_score(ppid);
    if (group_score >= KILL_THRESHOLD) {
    	log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "CREATE", NULL);
        log_message("그룹 임계치 초과: PPID=%d Score=%d (함수=CREATE)\n", ppid, group_score);
        // 동일한 PPID 가진 모든 child kill
        kill_all_children(ppid);
        // 부모 kill (공격자 bash 터미널 죽음)
        kill(ppid, SIGKILL);
        // 현재도 kill
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        
        reset_group_score(ppid);
        reset_malice_score(current_pid);
        return -EIO;
    }

    if (!is_writable_whitelisted(path)) {
        return -EACCES; 
    }
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    res = openat(base_fd, relpath, fi->flags | O_CREAT, mode);
    if (res == -1) return -errno;
    fi->fh = res;
    return 0;
}

// read
static int myfs_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
    // 더미 파일 체크
    if (is_dummy_file(path)) {
        block_process_on_dummy_access(path);
        return -EACCES;
    }
    
    //(12일 과제)
    struct fuse_context *context = fuse_get_context();
    if (context == NULL) {
        return -EIO;
    }
    pid_t current_pid = context->pid;
    int added_score = get_score("READ", NULL, NULL, 0);
    update_malice_score(current_pid, added_score);
    //PPID 점수 누적
    pid_t ppid = get_ppid_of(current_pid);
    update_group_score(ppid, added_score);

    // PID 점수 검사
    int pid_score = get_malice_score(current_pid);
    if (pid_score >= KILL_THRESHOLD) {

        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "READ", NULL);
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        return -EIO;
    }

    // 그룹(PPID) 점수 검사 
    int group_score = get_group_score(ppid);
    if (group_score >= KILL_THRESHOLD) {

        log_message("그룹 임계치 초과: PPID=%d Score=%d (함수=READ)\n", ppid, group_score);
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "READ", NULL);
        // 동일한 PPID 가진 모든 child kill
        kill_all_children(ppid);
        // 부모 kill (공격자 bash 터미널 죽음)
        kill(ppid, SIGKILL);
        // 현재도 kill
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        
        reset_group_score(ppid);
        reset_malice_score(current_pid);
        return -EIO;
    }
    
    int res;
    res = pread(fi->fh, buf, size, offset);
    if (res == -1) res = -errno;
    return res;
}

// write
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    // 복구 모듈: 파일 쓰기 전 백업
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
    
    // 더미 파일 체크
    if (is_dummy_file(path)) {
        block_process_on_dummy_access(path);
        return -EACCES;
    }
    
    // 랜섬웨어 확장자 체크
    if (is_ransomware_extension(path)) {
        struct fuse_context *context = fuse_get_context();
        pid_t current_pid = context ? context->pid : 0;
        restore_backup_file(path, base_fd);
        log_kill_ransomware_extension(current_pid, path, "WRITE", NULL);
        if (context && kill(current_pid, SIGKILL) == -1) {
            log_message("킬명령어 실패: %s\n", strerror(errno));
        }
        return -EACCES;
    }
    
    if (!is_writable_whitelisted(path)) {
        return -EACCES; 
    }
    
    
    
    
    
    //(12일 과제)
    struct fuse_context *context = fuse_get_context();
    if (context == NULL) {
        return -EIO;
    }
    pid_t current_pid = context->pid;
    char *old_buf = NULL; 
    int added_score = 0;

    if (size > 0) {
        old_buf = malloc(size); 
        if (old_buf == NULL) {
            log_message("메모리 할당 실패\n");
            return -ENOMEM;
        }
        
        ssize_t read_bytes = pread(fi->fh, old_buf, size, offset);
        if(read_bytes >= 0){
            added_score = get_score("WRITE", buf, old_buf, size);
        } else {
            added_score = get_score("WRITE", buf, NULL, size);
        }
        free(old_buf); 
    } else {  
        added_score = get_score("WRITE", buf, NULL, size);
    }

    update_malice_score(current_pid, added_score);
   // PPID 그룹 점수 누적
    pid_t ppid = get_ppid_of(current_pid);
    update_group_score(ppid, added_score);

    // PID 기준 kill 검사
    int pid_score = get_malice_score(current_pid);
    if (pid_score >= KILL_THRESHOLD) {
    	restore_backup_file(path, base_fd);
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "WRITE", NULL);
        if (kill(current_pid, SIGKILL) == -1) {
            log_message("킬 명령어 실패: %s\n", strerror(errno));
        }
        return -EIO;
    }

    //  그룹(PPID) 기준 kill 검사
    int group_score = get_group_score(ppid);
    if (group_score >= KILL_THRESHOLD) {
    	restore_backup_file(path, base_fd);
        log_message("그룹 임계치 초과: PPID=%d Score=%d (함수=WRITE)\n", ppid, group_score);
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "WRITE", NULL);
        // 동일한 PPID 가진 모든 child kill
        kill_all_children(ppid);
        // 부모 kill (공격자 bash 터미널 죽음)
        kill(ppid, SIGKILL);
        // 현재도 kill
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        
        reset_group_score(ppid);
        reset_malice_score(current_pid);
        return -EIO;
    }
    
    int res;
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) {
        res = -errno;
        return res;
    }
    
    // 파일 크기 변화 분석 (쓰기 후 크기 체크)
    struct stat st;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    if (fstatat(base_fd, relpath, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (check_file_size_change(path, st.st_size, current_pid)) {
        // 1) 복구
        restore_backup_file(path, base_fd);
        log_kill_file_size_change(current_pid, pid_score, st.original_size, st.st_size, double ratio)
        // 2) kill
        if (kill(current_pid, SIGKILL) == -1) {
            log_message("킬 명령어 실패: %s\n", strerror(errno));
        }

        return -EIO;
    }
}
    
    
    // 구간별 엔트로피 패턴 감지
    if (detect_entropy_pattern(path, base_fd, current_pid)) {
        restore_backup_file(path, base_fd);
        log_kill_entropy_pattern(current_pid, pid_score, int pattern_count, int threshold)
        if (kill(current_pid, SIGKILL) == -1) {
            log_message("킬 명령어 실패: %s\n", strerror(errno));
        }
        return -EIO;
    }

    return res;
}

       

// release
static int myfs_release(const char *path, struct fuse_file_info *fi) {
    close(fi->fh);
    struct fuse_context *context = fuse_get_context();
    if (context != NULL) {
        pid_t current_pid = context->pid;
        reset_malice_score(current_pid);
    } 
    return 0;
}

// unlink
static int myfs_unlink(const char *path) {
    if (!is_writable_whitelisted(path)) {
        return -EACCES; 
    }
    restore_backup_on_write(path, base_fd);
    struct fuse_context *context = fuse_get_context();
    if (context == NULL) {
        return -EIO;
    }
    pid_t current_pid = context->pid;
    int added_score = get_score("UNLINK", NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    
    // PPID 그룹 점수 누적
    pid_t ppid = get_ppid_of(current_pid);
    update_group_score(ppid, added_score);

    // PID 기준 kill 검사
    int pid_score = get_malice_score(current_pid);
    if (pid_score >= KILL_THRESHOLD) {
    	restore_backup_file(path, base_fd);
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "UNLINK", NULL);
        if (kill(current_pid, SIGKILL) == -1) {
            log_message("킬 명령어 실패: %s\n", strerror(errno));
        }
        return -EIO;
    }

    //  그룹(PPID) 기준 kill 검사
    int group_score = get_group_score(ppid);
    if (group_score >= KILL_THRESHOLD) {
    	restore_backup_file(path, base_fd);
        log_message("그룹 임계치 초과: PPID=%d Score=%d (함수=UNLINK)\n", ppid, group_score);
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "UNLINK", NULL);
        // 동일한 PPID 가진 모든 child kill
        kill_all_children(ppid);
        // 부모 kill (공격자 bash 터미널 죽음)
        kill(ppid, SIGKILL);
        // 현재도 kill
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        
        reset_group_score(ppid);
        reset_malice_score(current_pid);
        return -EIO;
    }

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    res = unlinkat(base_fd, relpath, 0);
    if (res == -1) return -errno;
    return 0;
}

// mkdir
static int myfs_mkdir(const char *path, mode_t mode) {
    struct fuse_context *context = fuse_get_context();
    if (context == NULL) {
        return -EIO;
    }
    pid_t current_pid = context->pid;
    int added_score = get_score("MKDIR", NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    // PPID 그룹 점수 누적
    pid_t ppid = get_ppid_of(current_pid);
    update_group_score(ppid, added_score);

    // PID 기준 kill 검사
    int pid_score = get_malice_score(current_pid);
    if (pid_score >= KILL_THRESHOLD) {

        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "MKDIR", NULL);
        if (kill(current_pid, SIGKILL) == -1) {
            log_message("킬 명령어 실패: %s\n", strerror(errno));
        }
        return -EIO;
    }

    //  그룹(PPID) 기준 kill 검사
    int group_score = get_group_score(ppid);
    if (group_score >= KILL_THRESHOLD) {
    	
        log_message("그룹 임계치 초과: PPID=%d Score=%d (함수=MKDIR)\n", ppid, group_score);
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "MKDIR", NULL);
        // 동일한 PPID 가진 모든 child kill
        kill_all_children(ppid);
        // 부모 kill (공격자 bash 터미널 죽음)
        kill(ppid, SIGKILL);
        // 현재도 kill
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        
        reset_group_score(ppid);
        reset_malice_score(current_pid);
        return -EIO;
    }

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    res = mkdirat(base_fd, relpath, mode);
    if (res == -1) return -errno;
    return 0;
}

// rmdir
static int myfs_rmdir(const char *path) {
    struct fuse_context *context = fuse_get_context();
    if (context == NULL) {
        return -EIO;
    }
    pid_t current_pid = context->pid;
    int added_score = get_score("RMDIR", NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    // PPID 그룹 점수 누적
    pid_t ppid = get_ppid_of(current_pid);
    update_group_score(ppid, added_score);

    // PID 기준 kill 검사
    int pid_score = get_malice_score(current_pid);
    if (pid_score >= KILL_THRESHOLD) {
    	
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "RMDIR", NULL);
        if (kill(current_pid, SIGKILL) == -1) {
            log_message("킬 명령어 실패: %s\n", strerror(errno));
        }
        return -EIO;
    }

    //  그룹(PPID) 기준 kill 검사
    int group_score = get_group_score(ppid);
    if (group_score >= KILL_THRESHOLD) {
    	
        log_message("그룹 임계치 초과: PPID=%d Score=%d (함수=RMDIR)\n", ppid, group_score);
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "RMDIR", NULL);
        // 동일한 PPID 가진 모든 child kill
        kill_all_children(ppid);
        // 부모 kill (공격자 bash 터미널 죽음)
        kill(ppid, SIGKILL);
        // 현재도 kill
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        
        reset_group_score(ppid);
        reset_malice_score(current_pid);
        return -EIO;
    }

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    res = unlinkat(base_fd, relpath, AT_REMOVEDIR);
    if (res == -1) return -errno;
    return 0;
}

// rename
static int myfs_rename(const char *from, const char *to, unsigned int flags) {
    // 랜섬웨어 확장자 체크
    if (is_ransomware_extension(to)) {
        struct fuse_context *context = fuse_get_context();
        pid_t current_pid = context ? context->pid : 0;
        restore_backup_file(from, base_fd);
        log_kill_ransomware_extension(current_pid, to, "RENAME", from);
        if (context && kill(current_pid, SIGKILL) == -1) {
            log_message("킬명령어 실패: %s\n", strerror(errno));
        }
        return -EACCES;
    }
    
    if (!is_writable_whitelisted(to)) {
        return -EACCES; 
    }
    
    struct fuse_context *context = fuse_get_context();
    if (context == NULL) {
        return -EIO;
    }
    pid_t current_pid = context->pid;
    int added_score = get_score("RENAME", NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    // PPID 그룹 점수 누적
    pid_t ppid = get_ppid_of(current_pid);
    update_group_score(ppid, added_score);

    // PID 기준 kill 검사
    int pid_score = get_malice_score(current_pid);
    if (pid_score >= KILL_THRESHOLD) {
        restore_backup_file(from, base_fd);
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, from, "RENAME", NULL);
        if (kill(current_pid, SIGKILL) == -1) {
            log_message("킬 명령어 실패: %s\n", strerror(errno));
        }
        return -EIO;
    }

    //  그룹(PPID) 기준 kill 검사
    int group_score = get_group_score(ppid);
    if (group_score >= KILL_THRESHOLD) {
    	restore_backup_file(from, base_fd);
        log_message("그룹 임계치 초과: PPID=%d Score=%d (함수=RENAME)\n", ppid, group_score);
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, from, "RENAME", NULL);
        // 동일한 PPID 가진 모든 child kill
        kill_all_children(ppid);
        // 부모 kill (공격자 bash 터미널 죽음)
        kill(ppid, SIGKILL);
        // 현재도 kill
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        
        reset_group_score(ppid);
        reset_malice_score(current_pid);
        return -EIO;
    }

    int res;
    char relfrom[PATH_MAX];
    char relto[PATH_MAX];
    get_relative_path(from, relfrom);
    get_relative_path(to, relto);
    if (flags) return -EINVAL;
    
    // 파일 크기 추적 경로 업데이트
    update_file_size_entry_path(from, to);
    
    res = renameat(base_fd, relfrom, base_fd, relto);
    if (res == -1) return -errno;
    return 0;
}

// utimens
static int myfs_utimens(const char *path, const struct timespec tv[2],
                        struct fuse_file_info *fi) {
    struct fuse_context *context = fuse_get_context();
    if (context == NULL) {
        return -EIO;
    }
    pid_t current_pid = context->pid;
    int added_score = get_score("UTIMENS", NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    
    // PPID 그룹 점수 누적
    pid_t ppid = get_ppid_of(current_pid);
    update_group_score(ppid, added_score);

    // PID 기준 kill 검사
    int pid_score = get_malice_score(current_pid);
    if (pid_score >= KILL_THRESHOLD) {
    	
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "UTIMENS", NULL);
        if (kill(current_pid, SIGKILL) == -1) {
            log_message("킬 명령어 실패: %s\n", strerror(errno));
        }
        return -EIO;
    }

    //  그룹(PPID) 기준 kill 검사
    int group_score = get_group_score(ppid);
    if (group_score >= KILL_THRESHOLD) {
    	
        log_message("그룹 임계치 초과: PPID=%d Score=%d (함수=UTIMENS)\n", ppid, group_score);
        log_kill_malice_score(current_pid, pid_score, KILL_THRESHOLD, path, "UTIMENS", NULL);
        // 동일한 PPID 가진 모든 child kill
        kill_all_children(ppid);
        // 부모 kill (공격자 bash 터미널 죽음)
        kill(ppid, SIGKILL);
        // 현재도 kill
        if (kill(current_pid, SIGKILL) == -1)
            log_message("킬명령어 실패: %s\n", strerror(errno));
        
        reset_group_score(ppid);
        reset_malice_score(current_pid);
        return -EIO;
    }

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    if (fi != NULL && fi->fh != 0) {
        res = futimens(fi->fh, tv);
    } else {
        res = utimensat(base_fd, relpath, tv, 0);
    }
    if (res == -1) return -errno;
    return 0;
}

// 연산자 구조체
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

// main
int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mountpoint>\n", argv[0]);
        return -1;
    }
    
    // mountpoint = backend 동시에 사용
    char *mountpoint = realpath(argv[argc-1], NULL);
    if (!mountpoint) {
        perror("realpath");
        return -1;
    }
    
    //로거 초기화
    if (init_logger(NULL) != 0) {
        fprintf(stderr, "Warning: Logger initialization failed\n");
    }
    
    //log_message("INFO: Protecting backend path: %s\n", backend_path);
    
    base_fd = open(mountpoint, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
	perror("open");
	free(mountpoint);
	close_logger();
	return -1;
    }
    
    //free(mountpoint);
    
     
    // 복구 모듈 초기화
    if (restore_init(getenv("HOME"), mountpoint) != 0) {
        log_message("Warning: Restore module initialization failed\n");
    }
    
    // Whitelist 초기화: 기존 파일들을 화이트리스트에 등록
    log_message("INFO: Initializing whitelist...\n");
    scan_directory_recursive(mountpoint, ".");
    log_message("INFO: Whitelist initialized: %d files registered\n", get_whitelist_count());
    
    // Dummy File 초기화: 더미 파일 목록에 등록
    log_message("INFO: Initializing dummy files...\n");
    const char *dummy_files[] = {
        "/dummy_secret.txt",
        "/important_data.txt",
        "/private_key.pem",
        "/backup.db",
        "/confidential.doc",
        NULL
    };
    for (int i = 0; dummy_files[i] != NULL; i++) {
        if (add_to_dummy_list(dummy_files[i]) == 0) {
            log_message("INFO: Added dummy file: %s\n", dummy_files[i]);
        }
    }
    log_message("INFO: Dummy files initialized: %d files registered\n", get_dummy_file_count());
    free(mountpoint);
    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);
    close(base_fd);
    free_whitelist();
    free_dummy_list();
    close_logger();
    return ret;
} 
