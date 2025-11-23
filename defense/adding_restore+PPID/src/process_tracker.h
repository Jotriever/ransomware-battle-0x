#ifndef PROCESS_TRACKER_H
#define PROCESS_TRACKER_H

#include <sys/types.h>
#include <time.h>

#define MAX_TRACKED_PIDS 100

// PID별 Malice Score, 행동 정보 저장할 구조체
typedef struct {
    pid_t pid;             
    int malice_score;      
    time_t last_write_time; // 마지막 쓰기 연산 시간 
    char proc_name[32];  //  프로세스 이름 저장
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

#endif // PROCESS_TRACKER_H

