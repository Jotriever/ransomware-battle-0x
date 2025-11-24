#include "pattern_detector.h"
#include "entropy.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>

#define CHUNK_SIZE (1024 * 1024)  // 1MB 청크 크기
#define ENTROPY_THRESHOLD 4.2     // 높은 엔트로피 임계값 (기존과 동일)
#define PATTERN_REPEAT_THRESHOLD 4 // 패턴 반복 임계값 (4번 이상)
#define MIN_FILE_SIZE (CHUNK_SIZE * 2) // 최소 분석 파일 크기 (2MB 이상)

// 상대 경로 변환 (blue2.c의 get_relative_path와 동일한 로직)
static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/') {
            strncpy(relpath, path + 1, PATH_MAX - 1);
        } else {
            strncpy(relpath, path, PATH_MAX - 1);
        }
        relpath[PATH_MAX - 1] = '\0';
    }
}

// 파일의 구간별 엔트로피 패턴 분석
int detect_entropy_pattern(const char *file_path, int base_fd, pid_t pid) {
    char relpath[PATH_MAX];
    get_relative_path(file_path, relpath);
    
    // 파일 정보 가져오기
    struct stat st;
    if (fstatat(base_fd, relpath, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return 0; // 파일 정보를 가져올 수 없으면 분석 불가
    }
    
    // 일반 파일이 아니거나 최소 크기 미만이면 분석하지 않음
    if (!S_ISREG(st.st_mode) || st.st_size < MIN_FILE_SIZE) {
        return 0;
    }
    
    // 파일 열기
    int fd = openat(base_fd, relpath, O_RDONLY);
    if (fd == -1) {
        return 0; // 파일을 열 수 없으면 분석 불가
    }
    
    // 청크별 엔트로피 저장을 위한 배열 (동적 할당)
    size_t num_chunks = (st.st_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    double *chunk_entropies = malloc(num_chunks * sizeof(double));
    if (chunk_entropies == NULL) {
        close(fd);
        return 0;
    }
    
    // 파일을 청크 단위로 읽어서 엔트로피 계산
    char *buffer = malloc(CHUNK_SIZE);
    if (buffer == NULL) {
        free(chunk_entropies);
        close(fd);
        return 0;
    }
    
    size_t chunk_idx = 0;
    off_t offset = 0;
    
    while (offset < st.st_size && chunk_idx < num_chunks) {
        size_t read_size = (st.st_size - offset < CHUNK_SIZE) ? 
                          (st.st_size - offset) : CHUNK_SIZE;
        
        ssize_t bytes_read = pread(fd, buffer, read_size, offset);
        if (bytes_read <= 0) {
            break; // 읽기 실패 또는 EOF
        }
        
        // 청크의 엔트로피 계산
        chunk_entropies[chunk_idx] = calculate_entropy(buffer, bytes_read);
        chunk_idx++;
        offset += bytes_read;
    }
    
    close(fd);
    free(buffer);
    
    if (chunk_idx < 2) {
        free(chunk_entropies);
        return 0; // 최소 2개 청크가 필요
    }
    
    // 패턴 감지: 높은 엔트로피 구간과 낮은 엔트로피 구간의 반복 확인
    int pattern_count = 0;
    int in_high_entropy = 0;
    int in_low_entropy = 0;
    int high_chunk_count = 0;
    int low_chunk_count = 0;
    
    // 첫 번째 청크로 초기 상태 설정
    if (chunk_entropies[0] >= ENTROPY_THRESHOLD) {
        in_high_entropy = 1;
        high_chunk_count = 1;
    } else {
        in_low_entropy = 1;
        low_chunk_count = 1;
    }
    
    // 패턴 감지: 높은 엔트로피 구간 → 낮은 엔트로피 구간 → 높은 엔트로피 구간...
    for (size_t i = 1; i < chunk_idx; i++) {
        if (chunk_entropies[i] >= ENTROPY_THRESHOLD) {
            // 높은 엔트로피 청크
            if (in_low_entropy) {
                // 낮은 엔트로피 구간에서 높은 엔트로피 구간으로 전환
                // 이전 낮은 엔트로피 구간이 끝났으므로 패턴 카운트 증가
                if (low_chunk_count > 0 && high_chunk_count > 0) {
                    pattern_count++;
                }
                in_low_entropy = 0;
                low_chunk_count = 0;
                in_high_entropy = 1;
                high_chunk_count = 1;
            } else {
                high_chunk_count++;
            }
        } else {
            // 낮은 엔트로피 청크
            if (in_high_entropy) {
                // 높은 엔트로피 구간에서 낮은 엔트로피 구간으로 전환
                in_high_entropy = 0;
                in_low_entropy = 1;
                low_chunk_count = 1;
            } else {
                low_chunk_count++;
            }
        }
    }
    
    // 마지막 구간 처리
    if (high_chunk_count > 0 && low_chunk_count > 0) {
        pattern_count++;
    }
    
    free(chunk_entropies);
    
    // 패턴이 4번 이상 반복되면 감지
    if (pattern_count >= PATTERN_REPEAT_THRESHOLD) {
        log_kill_entropy_pattern(pid, file_path, pattern_count, PATTERN_REPEAT_THRESHOLD);
        return 1; // 패턴 감지됨
    }
    
    return 0; // 패턴 미감지
}

