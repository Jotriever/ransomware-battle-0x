#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>
#include "dummy_file.h"
#include "logger.h"
#include "process_tracker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

// 더미 파일(낚시 파일) 목록 구조
static char **dummy_file_list = NULL;
static int dummy_file_count = 0;
static int dummy_file_capacity = 0;

// 더미 파일 목록에 추가하는 함수
int add_to_dummy_list(const char *path) {
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
            log_message("Error: Failed to allocate memory for dummy file list\n");
            return -1;
        }
        dummy_file_list = new_list;
        dummy_file_capacity = new_capacity;
    }
    
    // 경로 복사 및 추가
    dummy_file_list[dummy_file_count] = strdup(path);
    if (dummy_file_list[dummy_file_count] == NULL) {
        log_message("Error: Failed to allocate memory for dummy file entry\n");
        return -1;
    }
    dummy_file_count++;
    
    return 0;
}

// 더미 파일인지 확인
int is_dummy_file(const char *path) {
    for (int i = 0; i < dummy_file_count; i++) {
        if (strcmp(path, dummy_file_list[i]) == 0) {
            return 1; // 더미 파일
        }
    }
    return 0; // 더미 파일 아님
}

// 더미 파일 접근 시 프로세스 차단 (Forensic Kill 전략)
// 반환값: 0 = 화이트리스트 프로세스 (허용), -1 = 차단됨
int block_process_on_dummy_access(const char *path) {
    struct fuse_context *context = fuse_get_context();
    if (context) {
        pid_t current_pid = context->pid;
        
        // 화이트리스트 프로세스는 더미 파일 접근 허용 (정상 도구 보호)
        if (is_whitelisted_process(current_pid)) {
            log_message("INFO: 화이트리스트 프로세스가 더미 파일 접근 (PID=%d, 파일=%s) - 허용\n", 
                       current_pid, path);
            return 0; // 차단하지 않고 허용
        }
        
        log_kill_dummy_file(current_pid, path);
        
        // 1. 더미 파일 접근 플래그 설정 (행위 기반 필터링을 위해)
        set_dummy_access_flag(current_pid);
        
        log_message("🕵️ [SENTRY] 이름 없는 적 탐지 모드 가동 (PID=%d, 파일=%s)\n", current_pid, path);
        
        // 2. Forensic Kill 전략: 실행 파일 경로 기반 추적
        // - 프로세스 이름은 무시하고 실행 파일 경로만 추적
        // - 같은 실행 파일에서 실행된 모든 프로세스를 kill
        // - 실행 파일 자체에 락을 걸어 재실행 방지
        forensic_kill_by_exe_path(current_pid);
    }
    return -1; // 차단됨
}

// 더미 파일 목록 메모리 해제
void free_dummy_list(void) {
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

// 더미 파일 항목 수 반환
int get_dummy_file_count(void) {
    return dummy_file_count;
}

// 더미 파일 경로 반환 (인덱스 기반)
const char* get_dummy_file_path(int index) {
    if (index >= 0 && index < dummy_file_count) {
        return dummy_file_list[index];
    }
    return NULL;
}

