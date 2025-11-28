#ifndef PATTERN_DETECTOR_H
#define PATTERN_DETECTOR_H

#include <sys/types.h>

/**
 * @brief 파일의 구간별 엔트로피 패턴을 분석하여 반복 패턴 감지
 * @param file_path 분석할 파일의 FUSE 경로
 * @param base_fd 백엔드 디렉토리 파일 디스크립터
 * @param pid 프로세스 ID
 * @return 패턴이 4번 이상 반복되면 1, 그렇지 않으면 0
 */
int detect_entropy_pattern(const char *file_path, int base_fd, pid_t pid);

#endif // PATTERN_DETECTOR_H

