#include "process_tracker.h"
#include <stdio.h>
#include <time.h>

// 전역 Score 테이블
static ProcessScore g_score_table[MAX_TRACKED_PIDS];
static int g_process_count = 0; // 현재 추적 중인 프로세스 개수

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

