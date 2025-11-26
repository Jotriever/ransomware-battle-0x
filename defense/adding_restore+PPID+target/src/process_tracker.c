#include "process_tracker.h"
#include "logger.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <stdlib.h>


// 전역 Score 테이블
static ProcessScore g_score_table[MAX_TRACKED_PIDS];
static int g_process_count = 0; // 현재 추적 중인 프로세스 개수

// PPID 그룹 점수 테이블
static PpidGroup g_group_table[MAX_TRACKED_PIDS];
static int g_group_count = 0;

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

// 동일한 PPID를 가진 모든 자식 PID를 종료하는 함수
void kill_all_children(pid_t ppid) {
    DIR *dir = opendir("/proc");
    if (!dir) return;

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        int pid = atoi(entry->d_name);
        if (pid <= 0) continue;

        char status_path[256];
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);

        FILE *fp = fopen(status_path, "r");
        if (!fp) continue;

        char buf[256];
        pid_t found_ppid = -1;

        while (fgets(buf, sizeof(buf), fp)) {
            if (strncmp(buf, "PPid:", 5) == 0) {
                sscanf(buf + 5, "%d", &found_ppid);
                break;
            }
        }
        fclose(fp);

        if (found_ppid == ppid) {
            kill(pid, SIGKILL);
        }
    }

    closedir(dir);
}


