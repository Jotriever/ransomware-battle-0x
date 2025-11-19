#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>
#include "dummy_file.h"
#include "logger.h"
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
int is_dummy_file(const char *path) {
    for (int i = 0; i < dummy_file_count; i++) {
        if (strcmp(path, dummy_file_list[i]) == 0) {
            return 1; // 더미 파일
        }
    }
    return 0; // 더미 파일 아님
}

// 더미 파일 접근 시 프로세스 차단
void block_process_on_dummy_access(const char *path) {
    struct fuse_context *context = fuse_get_context();
    if (context) {
        pid_t current_pid = context->pid;
        log_kill_dummy_file(current_pid, path);
        
        // 프로세스 강제 종료
        if (kill(current_pid, SIGKILL) == -1) {
            log_message("❌ 킬 명령어 실패: %s\n", strerror(errno));
        } else {
            log_message("✅ 프로세스 PID %d 강제 종료 완료\n", current_pid);
        }
    }
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

