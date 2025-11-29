/* analyzer.c (Final Fixed Version) */
#include "entropy.h"
#include "analyzer.h"
#include "logger.h"
#include <string.h> // strcmp, memcmp
#include <stddef.h> // size_t, NULL
#include <stdio.h> 

// --- 1. 내용 기반 가중치 (Content-based) ---
#define WEIGHT_WRITE 5           // 기본 쓰기 5점 
#define WEIGHT_HIGH_ENTROPY 20   // 20점 부여함
#define ENTROPY_THRESHOLD 4.3    

// --- 2. 행위 기반 가중치 (Behavior-based) ---
#define WEIGHT_MALICIOUS 20      // 삭제/변경 20점 (고위험)
#define WEIGHT_MALICIOUS_LOW 1   // 정찰 행위 1점 (저위험)
#define WEIGHT_DUMMY_FILE_ACCESS 75  // 더미 파일 접근 75점 (고위험, 하지만 즉시 kill하지 않음)

// --- 3. 맥락 기반 가중치 (Context-based) ---
#define WEIGHT_LARGE_WRITE 150   // 대용량 쓰기 즉시 차단
#define LARGE_WRITE_THRESHOLD (10 * 1024 * 1024) 

// --- 4. 암호화 탐지 가중치 (Entropy-based) ---
#define WEIGHT_RANSOMWARE_DETECTED 150 // 랜섬웨어 탐지 시 즉시 차단
#define HIGH_ENTROPY_FLOOR 7.0         // 암호화 의심 기준선 (7.0 이상)


// 저엔트로피 우회(Wiper) 공격 탐지를 위한 고유 바이트 계수 함수
 // (0000... 이나 AAAA... 같은 단순 반복 데이터를 잡아냄)
int count_unique_bytes(const char *buf, size_t size) {
    int seen[256] = {0};
    int unique = 0;

    // 전체를 다 검사하면 느릴 수 있으므로, 앞부분 4KB만 검사해도 충분함
    size_t check_size = (size > 4096) ? 4096 : size;

    for (size_t i = 0; i < check_size; i++) {
        unsigned char b = (unsigned char)buf[i];
        if (!seen[b]) {
            seen[b] = 1;
            unique++;
            if (unique > 4) return unique; // 4개 넘으면 정상 파일로 간주 (빠른 리턴)
        }
    }
    return unique;
}


// 파일 헤더(Magic Number) 검사 함수
int is_valid_file_header(const char *buf, size_t size) {
    if (size < 4) return 0; 

    // 1. 이미지 (JPG, PNG, GIF, BMP, TIF)
    if (size >= 3 && memcmp(buf, "\xFF\xD8\xFF", 3) == 0) return 1;
    if (size >= 4 && memcmp(buf, "\x89\x50\x4E\x47", 4) == 0) return 1;
    if (size >= 6 && (memcmp(buf, "GIF87a", 6) == 0 || memcmp(buf, "GIF89a", 6) == 0)) return 1;
    if (size >= 2 && memcmp(buf, "BM", 2) == 0) return 1;
    if (size >= 4 && (memcmp(buf, "II*\x00", 4) == 0 || memcmp(buf, "MM\x00*", 4) == 0)) return 1;

    // 2. 문서 및 압축 (ZIP, Office, APK, JAR)
    if (size >= 2 && memcmp(buf, "PK", 2) == 0) return 1;
    // PDF
    if (size >= 4 && memcmp(buf, "%PDF", 4) == 0) return 1;
    // HWP
    if (size >= 8 && memcmp(buf, "\xD0\xCF\x11\xE0", 4) == 0) return 1;

    // 3. 미디어 (MP4, AVI, MP3)
    if (size >= 12 && memcmp(buf + 4, "ftyp", 4) == 0) return 1;
    if (size >= 4 && memcmp(buf, "RIFF", 4) == 0) return 1;
    if (size >= 3 && memcmp(buf, "ID3", 3) == 0) return 1;
    if (size >= 2 && (unsigned char)buf[0] == 0xFF && ((unsigned char)buf[1] & 0xE0) == 0xE0) return 1;

    // 4. 실행 파일 & DB
    if (size >= 4 && memcmp(buf, "\x7F\x45\x4C\x46", 4) == 0) return 1; // ELF
    if (size >= 2 && memcmp(buf, "MZ", 2) == 0) return 1; // Windows .exe
    if (size >= 16 && memcmp(buf, "SQLite format 3", 15) == 0) return 1; // SQLite

    return 0; 
}


// 악성 점수 반환
int get_score(const char* operation, const char* new_buf, const char* old_buf_or_null __attribute__((unused)), size_t size) {
    int score_to_add = 0;

    // --- [1] WRITE (쓰기) 연산 분석 ---
    if (strcmp(operation, "WRITE") == 0) {
        score_to_add += WEIGHT_WRITE; // 기본 5점 부여

        if (new_buf != NULL && size > 0) {
            
            // [추가된 방어] 저엔트로피 우회(Wiper) 탐지
            // 1MB 이상 쓰는데 고유 문자가 2개 이하라면? (예: 0000... 또는 AAAA...)
            if (size >= (1 * 1024 * 1024)) {
                int uniq = count_unique_bytes(new_buf, size);
                if (uniq <= 2) {
                     log_message("INFO: Wiper 공격 의심 (저엔트로피 우회): 고유 바이트 수=%d, 크기=%zu bytes\n", uniq, size);
                     score_to_add += WEIGHT_RANSOMWARE_DETECTED; // 150점 (즉시 차단)
                }
            }

            // 기존 엔트로피 분석
            double new_entropy = calculate_entropy(new_buf, size);
            
            // "결과물이 암호화 데이터(7.0 이상)인가?" 확인
            if (new_entropy > HIGH_ENTROPY_FLOOR) {
                
                // 7.0이 넘는 고엔트로피 데이터라면, 정상 파일(JPG, ZIP)인지 신분증 검사
                if (is_valid_file_header(new_buf, size)) {
                    // [PASS] 정상 파일임. 점수 부여 안 함.
                } 
                else {
                    // [BLOCK] 엔트로피는 높은데 헤더가 비정상 -> 랜섬웨어!
                    log_message("INFO: 고엔트로피 암호화 데이터 의심: 엔트로피=%.2f, 크기=%zu bytes (정상 파일 헤더 없음)\n", new_entropy, size);
                    score_to_add += WEIGHT_RANSOMWARE_DETECTED; // 150점 (즉시 차단)
                }
            }
        }
        
        // [대용량 쓰기 방어] (엔트로피와 무관하게 검사)
        if (size > LARGE_WRITE_THRESHOLD) {
            log_message("INFO: 대용량 쓰기 감지: 크기=%zu bytes (임계값: %d bytes)\n", size, LARGE_WRITE_THRESHOLD);
            score_to_add += WEIGHT_LARGE_WRITE; // 150점 (즉시 차단)
        }

    } 
    // --- [2] 고위험 행위 (삭제/변경) ---
    else if (strcmp(operation, "UNLINK") == 0 || strcmp(operation, "RENAME") == 0) {
        score_to_add += WEIGHT_MALICIOUS; // 20점
    } 
    // --- [3] 저위험 정찰 행위 (읽기/탐색) ---
    else if (strcmp(operation, "READ") == 0 ||
             strcmp(operation, "OPEN") == 0 ||
             strcmp(operation, "READDIR") == 0 ||
             strcmp(operation, "GETATTR") == 0) {
        score_to_add += WEIGHT_MALICIOUS_LOW; // 1점
    
    // --- [4] 기타 조작 행위 ---
    } else if (strcmp(operation, "CREATE") == 0 ||
               strcmp(operation, "MKDIR") == 0 ||
               strcmp(operation, "RMDIR") == 0 ||
               strcmp(operation, "UTIMENS") == 0) {
        score_to_add += WEIGHT_MALICIOUS_LOW; // 1점
    }

    return score_to_add;
}
