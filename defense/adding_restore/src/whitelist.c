#include "whitelist.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>

#define MAX_WHITELIST_SIZE 10000  // 최대 화이트리스트 항목 수

// 동적 화이트리스트 구조
static char **writable_whitelist = NULL;
static int whitelist_count = 0;
static int whitelist_capacity = 0;

// 화이트리스트에 경로 추가
int add_to_whitelist(const char *path) {
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
            log_message("Error: Failed to allocate memory for whitelist\n");
            return -1;
        }
        writable_whitelist = new_list;
        whitelist_capacity = new_capacity;
    }
    
    // 경로 복사 및 추가
    writable_whitelist[whitelist_count] = strdup(path);
    if (writable_whitelist[whitelist_count] == NULL) {
        log_message("Error: Failed to allocate memory for whitelist entry\n");
        return -1;
    }
    whitelist_count++;
    
    return 0;
}

// 해당 파일이 화이트리스트에 등록되어 있는지 확인
int is_writable_whitelisted(const char *path) {
    // 화이트리스트 배열에 등록된 파일만 허용
    for (int i = 0; i < whitelist_count; i++) {
        if (strcmp(path, writable_whitelist[i]) == 0) {
            return 1; // 화이트리스트에 등록된 파일 - 쓰기 허용
        }
    }
    return 0; // 화이트리스트에 없는 파일 - 쓰기 차단
}

// 화이트리스트 메모리 해제
void free_whitelist(void) {
    if (writable_whitelist != NULL) {
        for (int i = 0; i < whitelist_count; i++) {
            free(writable_whitelist[i]);
        }
        free(writable_whitelist);
        writable_whitelist = NULL;
        whitelist_count = 0;
        whitelist_capacity = 0;
    }
}

// 재귀적으로 디렉토리를 스캔하여 모든 파일을 화이트리스트에 추가
void scan_directory_recursive(const char *base_path, const char *relative_path) {
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
            log_message("INFO: Added to whitelist: %s\n", entry_fuse_path);
        }
        // 디렉토리면 재귀 호출
        else if (S_ISDIR(st.st_mode)) {
            scan_directory_recursive(base_path, entry_relative_path);
        }
    }
    
    closedir(dir);
}

// 화이트리스트 항목 수 반환
int get_whitelist_count(void) {
    return whitelist_count;
}

