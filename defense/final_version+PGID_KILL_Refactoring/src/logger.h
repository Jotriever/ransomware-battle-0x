#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef __unix__
#include <unistd.h>
#endif

// 로그 파일 초기화
int init_logger(const char *log_file_path);

// 로그 파일 닫기
void close_logger(void);

// 로그 메시지 출력 (stderr + 로그 파일)
void log_message(const char *format, ...);

// 킬링 메시지 출력 (형식화된 메시지)
void log_kill_dummy_file(pid_t pid, const char *path);
void log_kill_ransomware_extension(pid_t pid, const char *path, const char *operation, const char *from_path);
void log_kill_malice_score(pid_t pid, int score, int threshold, const char *path, const char *operation, const char *from_path);
void log_kill_entropy_pattern(pid_t pid, const char *path, int pattern_count, int threshold);
void log_kill_file_size_change(pid_t pid, const char *path, off_t original_size, off_t current_size, double ratio);

#endif // LOGGER_H

