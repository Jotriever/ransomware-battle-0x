#ifndef PROCESS_TRACKER_H
#define PROCESS_TRACKER_H

#include <sys/types.h>
#include <time.h>

#define MAX_TRACKED_PIDS 1000

// PID별 Malice Score, 행동 정보 저장할 구조체
typedef struct {
    pid_t pid;             
    int malice_score;      
    time_t last_write_time; // 마지막 쓰기 연산 시간 
    char proc_name[32];  //  프로세스 이름 저장
    int has_dummy_access;  // 더미 파일 접근 이력 (1: 있음, 0: 없음)
    int has_ransomware_ext; // 랜섬웨어 확장자 사용 이력 (1: 있음, 0: 없음)
} ProcessScore;

//PPID
typedef struct {
    pid_t ppid;
    int group_score;
} PpidGroup;


// 특정 PID의 Malice Score 업데이트, 마지막 쓰기 시간 갱신
void update_malice_score(pid_t pid, int added_score);

// 특정 PID의 Malice Score 반환
int get_malice_score(pid_t pid);

// 프로세스 종료 시 Score 0으로 초기화
void reset_malice_score(pid_t pid);

int get_group_score(pid_t ppid);
void update_group_score(pid_t ppid, int added_score);
void reset_group_score(pid_t ppid);
pid_t get_ppid_of(pid_t pid);

// 프로세스 이름 가져오기
int get_process_name(pid_t pid, char *name_buf, size_t buf_size);

// 화이트리스트 프로세스인지 확인 (정상 프로세스 보호)
int is_whitelisted_process(pid_t pid);

// 더미 파일 접근 이력 설정
void set_dummy_access_flag(pid_t pid);

// 랜섬웨어 확장자 사용 이력 설정
void set_ransomware_ext_flag(pid_t pid);

// 더미 파일 접근 이력 확인
int has_dummy_file_access(pid_t pid);

// 랜섬웨어 확장자 사용 이력 확인
int has_ransomware_extension_usage(pid_t pid);

// 직접 자식 프로세스 찾기 (최대 max_children개)
int find_direct_children(pid_t ppid, pid_t *children, int max_children);

// Freeze-then-Sweep: 프로세스 그룹을 먼저 멈춘 후 kill
void freeze_and_kill_process_group(pid_t target_pid);

// 실행 파일 경로 기반 추적 (Forensic Kill)
// 프로세스의 실행 파일 경로 가져오기
int get_process_exe_path(pid_t pid, char *exe_path, size_t path_size);

// 같은 실행 파일 경로를 가진 모든 프로세스 찾기
int find_processes_by_exe_path(const char *exe_path, pid_t *pids, int max_pids);

// 실행 파일 락 (chmod 000)
int lock_executable_file(const char *exe_path);

// 실행 파일 경로 기반 forensic kill (이름 무관, 경로로 추적)
void forensic_kill_by_exe_path(pid_t target_pid);

// /proc 스캔 콜백 함수 타입
typedef int (*proc_scan_callback_t)(pid_t pid, void *user_data);

// /proc 디렉토리를 스캔하며 각 프로세스에 대해 콜백 함수 호출 (공통 함수)
int scan_proc_directory(proc_scan_callback_t callback, void *user_data);


#endif // PROCESS_TRACKER_H

