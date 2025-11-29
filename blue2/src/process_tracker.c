#include "process_tracker.h"
#include "logger.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

// Freeze-then-Sweep 대기 시간 (50ms)
#define FREEZE_WAIT_TIME_US 50000

// 실행 파일 락 지속 시간 (5분 = 300초)
#define EXECUTABLE_LOCK_DURATION_SEC 300

// 락된 실행 파일 정보 구조체
typedef struct {
    char exe_path[PATH_MAX];
    time_t lock_time;  // 락이 걸린 시간 (타임스탬프)
    mode_t original_mode;  // 원본 권한 (복구용)
} LockedExecutable;

// 락된 실행 파일 목록
static LockedExecutable g_locked_executables[256];
static int g_locked_count = 0;

// 전역 Score 테이블
static ProcessScore g_score_table[MAX_TRACKED_PIDS];
static int g_process_count = 0; // 현재 추적 중인 프로세스 개수

// PPID 그룹 점수 테이블
static PpidGroup g_group_table[MAX_TRACKED_PIDS];
static int g_group_count = 0;

// find_direct_children용 콜백 함수 데이터 구조체
struct find_children_data {
    pid_t ppid;
    pid_t *children;
    int max_children;
    int *count;
};

// find_processes_by_exe_path용 콜백 함수 데이터 구조체
struct find_exe_path_data {
    const char *exe_path;
    pid_t *pids;
    int max_pids;
    int *count;
};

// 콜백 함수 선언
static int find_children_callback(pid_t pid, void *user_data);
static int find_exe_path_callback(pid_t pid, void *user_data);

/////////////////////////
// 같은 PPID를 가진 '악성 의심' PID가 몇 개 있는지 계산
static int count_offender_processes_with_ppid(pid_t ppid) {
    int count = 0;

    for (int i = 0; i < g_process_count; i++) {
        ProcessScore *entry = &g_score_table[i];

        // 아직 점수 0인 애는 무시 (행동 안 한 프로세스)
        if (entry->malice_score <= 0)
            continue;

        pid_t entry_ppid = get_ppid_of(entry->pid);
        if (entry_ppid == ppid) {
            count++;
        }
    }

    return count;
}



// ProcessScore 엔트리를 찾거나 새로 생성해 포인터 반환
static ProcessScore* find_or_create_score_entry(pid_t pid) {
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
        new_entry->has_dummy_access = 0;
        new_entry->has_ransomware_ext = 0;
        new_entry->proc_name[0] = '\0';
        // 프로세스 이름 가져오기 시도
        get_process_name(pid, new_entry->proc_name, sizeof(new_entry->proc_name));
        g_process_count++; // 추적 중인 프로세스 수 증가
        
        return new_entry;
    }
    
    // 배열이 가득 찼을 때 
    log_message("오류: 최대 PID 추적 개수 초과!\n");
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

// 부모 PID 조회 함수
pid_t get_ppid_of(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char buf[256];
    while (fgets(buf, sizeof(buf), fp)) {
        if (strncmp(buf, "PPid:", 5) == 0) {
            fclose(fp);
            return atoi(buf + 5);
        }
    }

    fclose(fp);
    return -1;
}

// /proc 디렉토리를 스캔하며 각 프로세스에 대해 콜백 함수 호출 (공통 함수)
int scan_proc_directory(proc_scan_callback_t callback, void *user_data) {
    if (!callback) {
        return -1;
    }
    
    DIR *dir = opendir("/proc");
    if (!dir) {
        return -1;
    }
    
    int count = 0;
    struct dirent *entry;
    
    while ((entry = readdir(dir)) != NULL) {
        int pid = atoi(entry->d_name);
        if (pid <= 0) continue;
        
        // 콜백 함수 호출
        if (callback(pid, user_data) == 0) {
            count++;
        }
    }
    
    closedir(dir);
    return count;
}

// 그룹 엔트리 찾기
static PpidGroup* find_or_create_group_entry(pid_t ppid) {
    for (int i = 0; i < g_group_count; i++) {
        if (g_group_table[i].ppid == ppid)
            return &g_group_table[i];
    }

    if (g_group_count < MAX_TRACKED_PIDS) {
        PpidGroup *new_entry = &g_group_table[g_group_count++];
        new_entry->ppid = ppid;
        new_entry->group_score = 0;
        return new_entry;
    }

    log_message("오류: 최대 그룹 추적 개수 초과!\n");
    return NULL;
}

// 그룹 점수 업데이트
void update_group_score(pid_t ppid, int added_score) {
    if (ppid <= 1) return; // systemd 등은 무시
    
    //////////////멀티프로세싱 여부 판단:
    // 같은 PPID를 가진 악성 의심 PID가 2개 이상일 때만 그룹 점수 올림
    int offenders = count_offender_processes_with_ppid(ppid);
    if (offenders < 2) {
        // 아직은 “멀티프로세싱 공격”으로 보지 않음 → 그룹 스코어 올리지 않음
        return;
    }

    PpidGroup *entry = find_or_create_group_entry(ppid);
    if (entry) {
        entry->group_score += added_score;
    }
}

// 그룹 점수 읽기
int get_group_score(pid_t ppid) {
    PpidGroup *entry = find_or_create_group_entry(ppid);
    if (entry) return entry->group_score;
    return 0;
}

// 그룹 점수 리셋
void reset_group_score(pid_t ppid) {
    PpidGroup *entry = find_or_create_group_entry(ppid);
    if (entry) entry->group_score = 0;
}


// 프로세스 이름 가져오기
int get_process_name(pid_t pid, char *name_buf, size_t buf_size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    
    FILE *fp = fopen(path, "r");
    if (!fp) {
        // comm 파일이 없으면 status 파일에서 가져오기 시도
        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        fp = fopen(path, "r");
        if (!fp) {
            if (name_buf && buf_size > 0) {
                name_buf[0] = '\0';
            }
            return -1;
        }
        
        // status 파일에서 Name: 필드 찾기
        char buf[256];
        while (fgets(buf, sizeof(buf), fp)) {
            if (strncmp(buf, "Name:", 5) == 0) {
                // "Name:\tprocess_name\n" 형식에서 이름 추출
                char *name_start = buf + 5;
                while (*name_start == ' ' || *name_start == '\t') {
                    name_start++;
                }
                // 개행 문자 제거
                char *newline = strchr(name_start, '\n');
                if (newline) *newline = '\0';
                
                if (name_buf && buf_size > 0) {
                    strncpy(name_buf, name_start, buf_size - 1);
                    name_buf[buf_size - 1] = '\0';
                }
                fclose(fp);
                return 0;
            }
        }
        fclose(fp);
        if (name_buf && buf_size > 0) {
            name_buf[0] = '\0';
        }
        return -1;
    }
    
    // comm 파일에서 읽기 (더 간단함)
    if (fgets(name_buf, buf_size, fp)) {
        // 개행 문자 제거
        char *newline = strchr(name_buf, '\n');
        if (newline) *newline = '\0';
        fclose(fp);
        return 0;
    }
    
    fclose(fp);
    if (name_buf && buf_size > 0) {
        name_buf[0] = '\0';
    }
    return -1;
}

// 화이트리스트 프로세스 목록 (정상 프로세스 보호)
static const char *whitelisted_processes[] = {
    "bash", "sh", "zsh", "fish", "dash", "csh", "tcsh",  // 쉘
    "sshd", "systemd", "init", "systemd-logind",  // 시스템 프로세스
    "vim", "vi", "nano", "emacs",  // 에디터
    "python", "python3", "python2",  // Python 인터프리터
    "gcc", "g++", "make", "cmake",  // 빌드 도구
    "ls", "cat", "grep", "find", "ps", "top", "htop",  // 유틸리티
    "blue2",  // FUSE 파일시스템 자체
    "file_integrity_checker",  // 파일 무결성 검사 도구
    NULL
};

// 화이트리스트 프로세스인지 확인
int is_whitelisted_process(pid_t pid) {
    char proc_name[64];
    if (get_process_name(pid, proc_name, sizeof(proc_name)) != 0) {
        return 0; // 이름을 가져올 수 없으면 화이트리스트 아님
    }
    
    for (int i = 0; whitelisted_processes[i] != NULL; i++) {
        if (strcmp(proc_name, whitelisted_processes[i]) == 0) {
            return 1; // 화이트리스트에 있음
        }
    }
    
    return 0; // 화이트리스트에 없음
}

// 더미 파일 접근 이력 설정
void set_dummy_access_flag(pid_t pid) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    if (entry) {
        entry->has_dummy_access = 1;
        // 프로세스 이름도 업데이트
        if (entry->proc_name[0] == '\0') {
            get_process_name(pid, entry->proc_name, sizeof(entry->proc_name));
        }
    }
}

// 랜섬웨어 확장자 사용 이력 설정
void set_ransomware_ext_flag(pid_t pid) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    if (entry) {
        entry->has_ransomware_ext = 1;
        // 프로세스 이름도 업데이트
        if (entry->proc_name[0] == '\0') {
            get_process_name(pid, entry->proc_name, sizeof(entry->proc_name));
        }
    }
}

// 더미 파일 접근 이력 확인
int has_dummy_file_access(pid_t pid) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    if (entry) {
        return entry->has_dummy_access;
    }
    return 0;
}

// 랜섬웨어 확장자 사용 이력 확인
int has_ransomware_extension_usage(pid_t pid) {
    ProcessScore *entry = find_or_create_score_entry(pid);
    if (entry) {
        return entry->has_ransomware_ext;
    }
    return 0;
}

// find_direct_children용 콜백 함수
static int find_children_callback(pid_t pid, void *user_data) {
    struct find_children_data *data = (struct find_children_data *)user_data;
    
    if (*data->count >= data->max_children) {
        return 1; // 더 이상 추가 불가
    }
    
    pid_t found_ppid = get_ppid_of(pid);
    if (found_ppid == data->ppid) {
        data->children[(*data->count)++] = pid;
    }
    
    return 0; // 계속 스캔
}

// 직접 자식 프로세스 찾기 (최대 max_children개) - 공통 /proc 스캔 함수 사용
int find_direct_children(pid_t ppid, pid_t *children, int max_children) {
    if (!children || max_children <= 0) {
        return 0;
    }
    
    int count = 0;
    struct find_children_data data = {ppid, children, max_children, &count};
    
    scan_proc_directory(find_children_callback, &data);
    return count;
}


// Freeze-then-Sweep: 프로세스 그룹을 먼저 멈춘 후 kill
void freeze_and_kill_process_group(pid_t target_pid) {
    pid_t pgid = getpgid(target_pid);
    if (pgid <= 0) {
        log_message("WARNING: 프로세스 그룹 ID를 가져올 수 없음 (PID=%d), 개별 kill 시도\n", target_pid);
        kill(target_pid, SIGKILL);
        return;
    }
    
    // 현재 프로세스 그룹과 같으면 자폭 방지
    if (pgid == getpgid(getpid())) {
        log_message("WARNING: 현재 프로세스 그룹과 동일 (PGID=%d), 개별 kill 시도\n", pgid);
        kill(target_pid, SIGKILL);
        return;
    }
    
    log_message("INFO: Freeze-then-Sweep 시작 (PGID=%d, PID=%d)\n", pgid, target_pid);
    
    // Step 1: FREEZE - 프로세스 그룹 전체를 SIGSTOP으로 멈춤
    if (killpg(pgid, SIGSTOP) == -1) {
        log_message("❌ 프로세스 그룹 FREEZE 실패 (PGID=%d): %s, 개별 FREEZE 시도\n", pgid, strerror(errno));
        
        // killpg 실패 시 개별 프로세스에 SIGSTOP
        DIR *dir = opendir("/proc");
        if (dir) {
            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL) {
                int pid = atoi(entry->d_name);
                if (pid <= 0 || pid == getpid()) continue;
                
                if (getpgid(pid) == pgid) {
                    kill(pid, SIGSTOP);
                }
            }
            closedir(dir);
        }
    } else {
        log_message("✅ 프로세스 그룹 FREEZE 성공 (PGID=%d) - 모든 프로세스가 멈춤\n", pgid);
    }
    
    // Step 2: 잠시 대기 (모든 프로세스가 멈출 시간 확보)
    // 50ms 대기 (fork() 실행 시간보다 충분히 길게)
    usleep(FREEZE_WAIT_TIME_US);
    
    // Step 3: SWEEP - 멈춘 상태에서 프로세스 그룹 전체를 SIGKILL
    log_message("INFO: SWEEP 시작 - 멈춘 프로세스 그룹 전체 kill (PGID=%d)\n", pgid);
    
    // 먼저 killpg로 시도
    if (killpg(pgid, SIGKILL) == -1) {
        log_message("❌ 프로세스 그룹 SWEEP 실패 (PGID=%d): %s, 개별 SWEEP 시도\n", pgid, strerror(errno));
        
        // killpg 실패 시 /proc를 스캔하여 같은 PGID의 모든 프로세스를 개별 kill
        DIR *dir = opendir("/proc");
        if (dir) {
            struct dirent *entry;
            int killed_count = 0;
            while ((entry = readdir(dir)) != NULL) {
                int pid = atoi(entry->d_name);
                if (pid <= 0 || pid == getpid()) continue;
                
                if (getpgid(pid) == pgid) {
                    if (kill(pid, SIGKILL) == 0) {
                        killed_count++;
                        log_message("✅ 개별 프로세스 SWEEP 성공 (PID=%d, PGID=%d)\n", pid, pgid);
                    } else {
                        log_message("❌ 개별 프로세스 SWEEP 실패 (PID=%d): %s\n", pid, strerror(errno));
                    }
                }
            }
            closedir(dir);
            log_message("INFO: 개별 SWEEP 완료 - 총 %d개 프로세스 kill\n", killed_count);
        }
    } else {
        log_message("✅ 프로세스 그룹 SWEEP 성공 (PGID=%d) - 전체 프로세스 그룹 kill 완료\n", pgid);
    }
}

// 프로세스의 실행 파일 경로 가져오기 (/proc/[pid]/exe)
int get_process_exe_path(pid_t pid, char *exe_path, size_t path_size) {
    if (!exe_path || path_size == 0) {
        return -1;
    }
    
    char exe_link[64];
    snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
    
    // readlink로 심볼릭 링크 읽기
    ssize_t len = readlink(exe_link, exe_path, path_size - 1);
    if (len == -1) {
        // readlink 실패 (프로세스가 종료되었거나 접근 불가)
        exe_path[0] = '\0';
        return -1;
    }
    
    exe_path[len] = '\0';  // null 종료
    return 0;
}

// find_processes_by_exe_path용 콜백 함수
static int find_exe_path_callback(pid_t pid, void *user_data) {
    struct find_exe_path_data *data = (struct find_exe_path_data *)user_data;
    
    if (*data->count >= data->max_pids) {
        return 1; // 더 이상 추가 불가
    }
    
    char proc_exe_path[PATH_MAX];
    if (get_process_exe_path(pid, proc_exe_path, sizeof(proc_exe_path)) == 0) {
        if (strcmp(proc_exe_path, data->exe_path) == 0) {
            data->pids[(*data->count)++] = pid;
        }
    }
    
    return 0; // 계속 스캔
}

// 같은 실행 파일 경로를 가진 모든 프로세스 찾기 - 공통 /proc 스캔 함수 사용
int find_processes_by_exe_path(const char *exe_path, pid_t *pids, int max_pids) {
    if (!exe_path || !pids || max_pids <= 0) {
        return 0;
    }
    
    int count = 0;
    struct find_exe_path_data data = {exe_path, pids, max_pids, &count};
    
    scan_proc_directory(find_exe_path_callback, &data);
    return count;
}

// 만료된 실행 파일 락 자동 해제
static void unlock_expired_executable_files(void) {
    time_t current_time = time(NULL);
    
    for (int i = g_locked_count - 1; i >= 0; i--) {
        LockedExecutable *locked = &g_locked_executables[i];
        
        // 락 지속 시간이 지났는지 확인
        if (current_time - locked->lock_time >= EXECUTABLE_LOCK_DURATION_SEC) {
            // 파일 존재 여부 확인
            struct stat st;
            if (stat(locked->exe_path, &st) == -1) {
                // 파일이 삭제되었거나 이동됨
                log_message("INFO: 락된 실행 파일이 더 이상 존재하지 않음: %s\n", locked->exe_path);
            } else {
                // 원본 권한으로 복구
                if (chmod(locked->exe_path, locked->original_mode) == 0) {
                    log_message("🔓 [AUTO UNLOCK] 실행 파일 락 자동 해제: %s (원본 권한: %o)\n", 
                               locked->exe_path, locked->original_mode);
                } else {
                    log_message("❌ 실행 파일 락 해제 실패: %s (%s)\n", 
                               locked->exe_path, strerror(errno));
                }
            }
            
            // 목록에서 제거 (뒤에서부터 제거하므로 인덱스 유지)
            if (i < g_locked_count - 1) {
                g_locked_executables[i] = g_locked_executables[g_locked_count - 1];
            }
            g_locked_count--;
        }
    }
}

// 실행 파일 락 (chmod 000) - 일시적 락 (5분 후 자동 해제)
int lock_executable_file(const char *exe_path) {
    if (!exe_path) {
        return -1;
    }
    
    // 만료된 락 자동 해제
    unlock_expired_executable_files();
    
    // 기존 락 확인 (이미 락되어 있으면 시간만 갱신)
    for (int i = 0; i < g_locked_count; i++) {
        if (strcmp(g_locked_executables[i].exe_path, exe_path) == 0) {
            // 이미 락되어 있으면 시간만 갱신
            g_locked_executables[i].lock_time = time(NULL);
            log_message("🔒 [LOCK] 실행 파일 락 시간 갱신: %s (5분 연장)\n", exe_path);
            return 0;
        }
    }
    
    // 원본 권한 저장
    struct stat st;
    if (stat(exe_path, &st) == -1) {
        log_message("❌ 실행 파일 정보 가져오기 실패: %s (%s)\n", exe_path, strerror(errno));
        return -1;
    }
    mode_t original_mode = st.st_mode;
    
    // chmod 000으로 실행 권한 제거
    if (chmod(exe_path, 0) == -1) {
        log_message("❌ 실행 파일 락 실패: %s (%s)\n", exe_path, strerror(errno));
        return -1;
    }
    
    // 락 목록에 추가
    if (g_locked_count < 256) {
        strncpy(g_locked_executables[g_locked_count].exe_path, exe_path, PATH_MAX - 1);
        g_locked_executables[g_locked_count].exe_path[PATH_MAX - 1] = '\0';
        g_locked_executables[g_locked_count].lock_time = time(NULL);
        g_locked_executables[g_locked_count].original_mode = original_mode;
        g_locked_count++;
        
        log_message("🔒 [LOCK] 실행 파일 락 완료: %s (chmod 000, 5분 후 자동 해제, 원본 권한: %o)\n", 
                   exe_path, original_mode);
    } else {
        log_message("WARNING: 락 목록이 가득 참, 락은 걸렸지만 추적 불가\n");
    }
    
    return 0;
}

// 실행 파일 경로 기반 forensic kill (이름 무관, 경로로 추적)
void forensic_kill_by_exe_path(pid_t target_pid) {
    // 0단계: 화이트리스트 프로세스는 Forensic Kill 대상에서 제외 (정상 도구 보호)
    if (is_whitelisted_process(target_pid)) {
        char proc_name[64];
        get_process_name(target_pid, proc_name, sizeof(proc_name));
        log_message("INFO: 화이트리스트 프로세스 보호 (PID=%d, name=%s) - Forensic Kill 건너뜀\n", 
                   target_pid, proc_name);
        return; // 화이트리스트 프로세스는 kill하지 않음
    }
    
    char exe_path[PATH_MAX];
    
    // 1단계: 현행범의 실행 파일 경로 확보
    if (get_process_exe_path(target_pid, exe_path, sizeof(exe_path)) != 0) {
        log_message("WARNING: 실행 파일 경로를 가져올 수 없음 (PID=%d)\n", target_pid);
        // 실행 파일 경로를 못 찾으면 기존 방식으로 fallback
        freeze_and_kill_process_group(target_pid);
        return;
    }
    
    log_message("🕵️ [FORENSIC] 범인의 근거지 확인: %s (PID=%d)\n", exe_path, target_pid);
    
    // 2단계: 같은 실행 파일 경로를 가진 모든 프로세스 찾기
    pid_t related_pids[256];
    int pid_count = find_processes_by_exe_path(exe_path, related_pids, 256);
    
    if (pid_count == 0) {
        log_message("WARNING: 같은 실행 파일 경로를 가진 프로세스를 찾지 못함\n");
        // 프로세스를 못 찾으면 기존 방식으로 fallback
        freeze_and_kill_process_group(target_pid);
        return;
    }
    
    log_message("☢️ [소탕] 확인된 악성 실행 파일 경로: %s (총 %d개 프로세스 발견)\n", exe_path, pid_count);
    
    // 3단계: 원천 봉쇄 (실행 파일 락) - 먼저 락을 걸어 재실행 방지
    lock_executable_file(exe_path);
    
    // 4단계: Freeze-then-Sweep으로 모든 관련 프로세스 kill
    // 각 프로세스에 대해 Freeze-then-Sweep 적용
    int killed_count = 0;
    for (int i = 0; i < pid_count; i++) {
        pid_t pid = related_pids[i];
        
        // 현재 프로세스는 건드리지 않음 (자폭 방지)
        if (pid == getpid()) {
            log_message("WARNING: 현재 프로세스와 동일 (PID=%d), 건너뜀\n", pid);
            continue;
        }
        
        // 화이트리스트 프로세스는 건드리지 않음 (정상 도구 보호)
        if (is_whitelisted_process(pid)) {
            char proc_name[64];
            get_process_name(pid, proc_name, sizeof(proc_name));
            log_message("INFO: 화이트리스트 프로세스 보호 (PID=%d, name=%s) - 건너뜀\n", pid, proc_name);
            continue;
        }
        
        log_message("INFO: 관련 프로세스 kill 시도 (PID=%d, exe=%s)\n", pid, exe_path);
        freeze_and_kill_process_group(pid);
        killed_count++;
    }
    
    log_message("💀 [FORENSIC KILL] 연관 프로세스 총 %d개 중 %d개 사살 완료 (실행 파일: %s)\n", 
               pid_count, killed_count, exe_path);
}


