/* blue2.c (최종 수정본) */
#define FUSE_USE_VERSION 35
#define MAX_TRACKED_PIDS 100
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
#define KILL_THRESHOLD 100 //malice_score 임계값 (넘으면 강제 종료됨)   

static int base_fd = -1;

// 블랙리스트
static const char *blacklist[] = { "/ransomware.exe", NULL };

// 화이트리스트
static const char *writable_whitelist[] = { "/text.txt", NULL };

static int is_blacklisted(const char *path) {
    for (int i = 0; blacklist[i] != NULL; i++) {
        if (strcmp(path, blacklist[i]) == 0) return 1;
    }
    return 0; 
}

static int is_writable_whitelisted(const char *path) {
    for (int i = 0; writable_whitelist[i] != NULL; i++) {
        if (strcmp(path, writable_whitelist[i]) == 0) return 1;
    }
    return 0; 
}

typedef struct {
    pid_t pid;             
    int malice_score;      
    time_t last_write_time; 
    char proc_name[32];  
} ProcessScore;

ProcessScore g_score_table[MAX_TRACKED_PIDS];
int g_process_count = 0; 

ProcessScore* find_or_create_score_entry(pid_t pid) {
    for (int i = 0; i < g_process_count; i++) {
        if (g_score_table[i].pid == pid) return &g_score_table[i];
    }
    if (g_process_count < MAX_TRACKED_PIDS) {
        ProcessScore *new_entry = &g_score_table[g_process_count];
        new_entry->pid = pid;
        new_entry->malice_score = 0;
        new_entry->last_write_time = time(NULL);
        g_process_count++; 
        return new_entry;
    }
    fprintf(stderr, "오류: 최대 PID 추적 개수 초과!\n");
    return NULL;
}

void update_malice_score(pid_t pid, int added_score) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    if (entry) {
        entry->malice_score += added_score;
        entry->last_write_time = time(NULL); 
    }
}

int get_malice_score(pid_t pid) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    if (entry) return entry->malice_score;
    return 0; 
}

void reset_malice_score(pid_t pid) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    if (entry) entry->malice_score = 0;
}

static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/') path++;
        strncpy(relpath, path, PATH_MAX);
    }
}

// getattr
static int myfs_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi) {
    //(12일 과제)
    struct fuse_context *context = fuse_get_context(); 
    pid_t current_pid = context->pid;
    int added_score = get_score("GETATTR",NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {
            fprintf(stderr, "Kill ! 'GETATTR' 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1) fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
            return -EIO;
    }

    (void) fi;
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);
    res = fstatat(base_fd, relpath, stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1) return -errno;
    
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
    pid_t current_pid = context->pid;
    int added_score = get_score("READDIR",NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {
            fprintf(stderr, "Kill ! 'READDIR' 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1) fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
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
    //(12일 과제)
    struct fuse_context *context = fuse_get_context(); 
    pid_t current_pid = context->pid;
    int added_score = get_score("OPEN",NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {
            fprintf(stderr, "Kill ! 'OPEN' 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1) fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
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
    //(12일 과제)
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;
    int added_score = get_score("CREATE", NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {
            fprintf(stderr, "Kill ! 'CREATE' 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1) fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
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
    //(12일 과제)
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;
    int added_score = get_score("READ", NULL, NULL, 0);
    update_malice_score(current_pid, added_score);
    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {
        fprintf(stderr, "Kill ! 'READ' 임계값 초과! PID %d 강제종료\n", current_pid);
        if(kill(current_pid,SIGKILL) == -1) fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
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
    if (!is_writable_whitelisted(path)) {
        return -EACCES; 
    }
    //(12일 과제)
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;
    char *old_buf = NULL; 
    int added_score = 0;

    if (size > 0) {
        old_buf = malloc(size); 
        if (old_buf == NULL) {
            fprintf(stderr, "메모리 할당 실패\n");
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
    
    if (get_malice_score(current_pid) >= KILL_THRESHOLD) {
        fprintf(stderr, "Kill ! 'write' 임계값 초과! PID %d 강제 종료\n", current_pid);
        if (kill(current_pid, SIGKILL) == -1) {
            fprintf(stderr, "킬 명령어 실패: %s\n", strerror(errno));
        }
        return -EIO; 
    }

    int res;
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) res = -errno;
    return res;
}

// release
static int myfs_release(const char *path, struct fuse_file_info *fi) {
    close(fi->fh);
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;
    reset_malice_score(current_pid); 
    return 0;
}

// unlink
static int myfs_unlink(const char *path) {
    if (!is_writable_whitelisted(path)) {
        return -EACCES; 
    }
    
    struct fuse_context *context = fuse_get_context(); 
    pid_t current_pid = context->pid;
    int added_score = get_score("UNLINK", NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {
	    fprintf(stderr, "Kill ! 'unlink' 임계값 초과! PID %d 강제종료\n", current_pid);
	    if(kill(current_pid,SIGKILL) == -1) fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
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
    pid_t current_pid = context->pid;
    int added_score = get_score("MKDIR", NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {
            fprintf(stderr, "Kill ! 'MKDIR' 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1) fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
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
    pid_t current_pid = context->pid;
    int added_score = get_score("RMDIR", NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {
            fprintf(stderr, "Kill ! 'RMDIR' 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1) fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
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
    if (!is_writable_whitelisted(to)) {
        return -EACCES; 
    }
    
    struct fuse_context *context = fuse_get_context(); 
    pid_t current_pid = context->pid;
    int added_score = get_score("RENAME", NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {
            fprintf(stderr, "Kill ! 'rename' 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1) fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
            return -EIO;
    }
    int res;
    char relfrom[PATH_MAX];
    char relto[PATH_MAX];
    get_relative_path(from, relfrom);
    get_relative_path(to, relto);
    if (flags) return -EINVAL;
    res = renameat(base_fd, relfrom, base_fd, relto);
    if (res == -1) return -errno;
    return 0;
}

// utimens
static int myfs_utimens(const char *path, const struct timespec tv[2],
                        struct fuse_file_info *fi) {
    struct fuse_context *context = fuse_get_context(); 
    pid_t current_pid = context->pid;
    int added_score = get_score("UTIMENS", NULL, NULL, 0); 
    update_malice_score(current_pid, added_score); 
    if(get_malice_score(current_pid) >= KILL_THRESHOLD) {
            fprintf(stderr, "Kill ! 'UTIMENS' 임계값 초과! PID %d 강제종료\n", current_pid);
            if(kill(current_pid,SIGKILL) == -1) fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
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
    char *mountpoint = realpath(argv[argc - 1], NULL);
    if (mountpoint == NULL) {
        perror("realpath");
        return -1;
    }
    const char *home_dir = getenv("HOME");
    if (!home_dir) {
    	fprintf(stderr, "Error: HOME environment variable not set.\n");
        return -1;
    }
    char backend_path[PATH_MAX];
    snprintf(backend_path, PATH_MAX, "%s/workspace/target", home_dir);
    fprintf(stderr, "INFO: Protecting backend path: %s\n", backend_path);
    base_fd = open(backend_path, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
	perror("Error opening backend directory");
	return -1;
    }
    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);
    close(base_fd);
    return ret;
}
