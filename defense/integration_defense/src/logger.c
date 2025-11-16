#include "logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

static FILE *log_file = NULL;
static char log_file_path[512] = "./ransomware_defense.log";

// 로그 파일 초기화
int init_logger(const char *log_file_path_custom) {
    if (log_file_path_custom != NULL) {
        strncpy(log_file_path, log_file_path_custom, sizeof(log_file_path) - 1);
        log_file_path[sizeof(log_file_path) - 1] = '\0';
    }
    
    log_file = fopen(log_file_path, "a");
    if (log_file == NULL) {
        fprintf(stderr, "Warning: Cannot open log file %s: %s\n", log_file_path, strerror(errno));
        return -1;
    }
    
    // 로그 파일에 시작 메시지 기록
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(log_file, "\n========================================\n");
    fprintf(log_file, "Defense System Started\n");
    fprintf(log_file, "Time: %s\n", time_str);
    fprintf(log_file, "Log File: %s\n", log_file_path);
    fprintf(log_file, "========================================\n\n");
    fflush(log_file);
    
    return 0;
}

// 로그 파일 닫기
void close_logger(void) {
    if (log_file != NULL) {
        time_t now = time(NULL);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(log_file, "\n========================================\n");
        fprintf(log_file, "Defense System Stopped\n");
        fprintf(log_file, "Time: %s\n", time_str);
        fprintf(log_file, "========================================\n\n");
        fclose(log_file);
        log_file = NULL;
    }
}

// 로그 메시지 출력 (stderr + 로그 파일)
void log_message(const char *format, ...) {
    va_list args;
    
    // stderr에 출력
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    
    // 로그 파일에 출력
    if (log_file != NULL) {
        time_t now = time(NULL);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(log_file, "[%s] ", time_str);
        
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);
        
        fflush(log_file);
    }
}

// 더미 파일 접근 감지 킬링 메시지
void log_kill_dummy_file(pid_t pid, const char *path) {
    log_message("\n========================================\n");
    log_message("🚨 PROCESS KILLED - 더미 파일 접근 감지\n");
    log_message("========================================\n");
    log_message("사유: 더미 파일(낚시 파일) 접근 시도\n");
    log_message("PID: %d\n", pid);
    log_message("접근 시도한 파일: %s\n", path);
    log_message("조치: 프로세스 강제 종료 (SIGKILL)\n");
    log_message("========================================\n\n");
}

// 랜섬웨어 확장자 감지 킬링 메시지
void log_kill_ransomware_extension(pid_t pid, const char *path, const char *operation, const char *from_path) {
    log_message("\n========================================\n");
    log_message("🚨 PROCESS KILLED - 랜섬웨어 확장자 감지\n");
    log_message("========================================\n");
    if (from_path != NULL) {
        log_message("사유: 알려진 랜섬웨어 확장자로 이름 변경 시도\n");
        log_message("PID: %d\n", pid);
        log_message("원본 파일: %s\n", from_path);
        log_message("변경 시도한 파일: %s\n", path);
    } else {
        log_message("사유: 알려진 랜섬웨어 확장자 사용\n");
        log_message("PID: %d\n", pid);
        log_message("파일 경로: %s\n", path);
    }
    log_message("작업: %s\n", operation);
    log_message("조치: 프로세스 강제 종료 (SIGKILL)\n");
    log_message("========================================\n\n");
}

// Malice Score 임계값 초과 킬링 메시지
void log_kill_malice_score(pid_t pid, int score, int threshold, const char *path, const char *operation, const char *from_path) {
    log_message("\n========================================\n");
    log_message("🚨 PROCESS KILLED - Malice Score 임계값 초과\n");
    log_message("========================================\n");
    log_message("사유: 악성 행동 점수(Malice Score) 임계값 초과\n");
    log_message("PID: %d\n", pid);
    log_message("현재 Malice Score: %d\n", score);
    log_message("임계값: %d\n", threshold);
    if (from_path != NULL) {
        log_message("원본 파일: %s\n", from_path);
        log_message("변경 시도한 파일: %s\n", path);
    } else {
        log_message("파일 경로: %s\n", path);
    }
    log_message("작업: %s\n", operation);
    log_message("조치: 프로세스 강제 종료 (SIGKILL)\n");
    log_message("========================================\n\n");
}

// 구간별 엔트로피 패턴 감지 킬링 메시지
void log_kill_entropy_pattern(pid_t pid, const char *path, int pattern_count, int threshold) {
    log_message("\n========================================\n");
    log_message("🚨 PROCESS KILLED - 구간별 엔트로피 패턴 감지\n");
    log_message("========================================\n");
    log_message("사유: 반복적인 부분 암호화 패턴 감지\n");
    log_message("PID: %d\n", pid);
    log_message("파일 경로: %s\n", path);
    log_message("감지된 패턴 반복 횟수: %d\n", pattern_count);
    log_message("임계값: %d회 이상\n", threshold);
    log_message("작업: 파일 쓰기 (WRITE)\n");
    log_message("조치: 프로세스 강제 종료 (SIGKILL)\n");
    log_message("========================================\n\n");
}

