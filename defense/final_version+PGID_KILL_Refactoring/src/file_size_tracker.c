#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include "file_size_tracker.h"
#include "logger.h"
#include "restore.h" //복구

// 파일 크기 추적 테이블
static FileSizeEntry file_size_table[MAX_FILE_SIZE_TRACK];
static int file_size_count = 0;

// 파일 크기 추적 엔트리 찾기 또는 생성
FileSizeEntry* find_or_create_file_size_entry(const char *path) {
    // 기존 엔트리 검색
    for (int i = 0; i < file_size_count; i++) {
        if (strcmp(file_size_table[i].path, path) == 0) {
            return &file_size_table[i];
        }
    }
    
    // 새 엔트리 생성
    if (file_size_count < MAX_FILE_SIZE_TRACK) {
        FileSizeEntry *entry = &file_size_table[file_size_count];
        strncpy(entry->path, path, PATH_MAX - 1);
        entry->path[PATH_MAX - 1] = '\0';
        entry->is_tracked = 0;
        entry->original_size = 0;
        file_size_count++;
        return entry;
    }
    
    return NULL; // 테이블이 가득 참
}

// 파일 크기 변화 분석 (원본 대비 4/3배 비율 확인)
int check_file_size_change(const char *path, off_t current_size, pid_t pid) {
    FileSizeEntry *entry = find_or_create_file_size_entry(path);
    if (entry == NULL) {
        return 0;
    }
    
    // 원본 크기가 아직 저장되지 않았으면 현재 크기를 원본으로 저장
    if (entry->is_tracked == 0) {
        entry->original_size = current_size;
        entry->is_tracked = 1;
        return 0;
    }
    
    // 원본 크기가 0이면 분석 불가
    if (entry->original_size == 0) {
        return 0;
    }
    
    // 크기 변화 비율 계산 (4/3 = 1.333...)
    double ratio = (double)current_size / (double)entry->original_size;
    double target_ratio = 4.0 / 3.0; // Base64 인코딩 시 일반적인 크기 증가 비율
    double tolerance = 0.1; // 10% 허용 오차
    
    // 4/3배 비율 범위 내인지 확인 (1.23 ~ 1.43)
    if (ratio >= (target_ratio - tolerance) && ratio <= (target_ratio + tolerance)) {
        // Base64 인코딩 감지 - 프로세스 종료
        log_kill_file_size_change(pid, path, entry->original_size, current_size, ratio);
        if (kill(pid, SIGKILL) == -1) {
            log_message("킬 명령어 실패: %s\n", strerror(errno));
        }
        return 1; // 의심 (감지됨)
    }

    // [추가] 파일 사이즈 작아지는 지 탐지 탐지 (갑자기 작아지는 것)
    // 예: 원래 크기의 10% 미만으로 줄어들면 "파괴 행위"로 간주
    if (entry->original_size > 1024 && ratio < 0.1) {
        log_message("[DETECT] 파일 파괴(Wiper) 의심 (비율 급감): %s (%.1f%%)\n", path, ratio*100);
        return 1; // 차단!
    }

    return 0; // 정상
    
}

// 파일 경로 업데이트 (rename 시 사용)
void update_file_size_entry_path(const char *old_path, const char *new_path) {
    FileSizeEntry *entry = find_or_create_file_size_entry(old_path);
    if (entry != NULL && entry->is_tracked) {
        // 기존 경로의 엔트리를 새 경로로 업데이트
        strncpy(entry->path, new_path, PATH_MAX - 1);
        entry->path[PATH_MAX - 1] = '\0';
    }
}

