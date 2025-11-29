#ifndef FILE_SIZE_TRACKER_H
#define FILE_SIZE_TRACKER_H

#include <sys/types.h>
#include <limits.h>

// 파일 크기 추적을 위한 구조체
#define MAX_FILE_SIZE_TRACK 1000
typedef struct {
    char path[PATH_MAX];
    off_t original_size;
    int is_tracked;
} FileSizeEntry;

// 파일 크기 추적 엔트리 찾기 또는 생성
FileSizeEntry* find_or_create_file_size_entry(const char *path);

// 파일 크기 변화 분석 (원본 대비 4/3배 비율 확인)
int check_file_size_change(const char *path, off_t current_size, pid_t pid);

// 파일 경로 업데이트 (rename 시 사용)
void update_file_size_entry_path(const char *old_path, const char *new_path);

#endif // FILE_SIZE_TRACKER_H

