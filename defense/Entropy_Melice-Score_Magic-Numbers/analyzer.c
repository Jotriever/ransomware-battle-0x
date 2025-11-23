/* analyzer.c (Final Fixed Version) */
#include "entropy.h"
#include "analyzer.h"
#include <string.h> // strcmp, memcmp
#include <stddef.h> // size_t, NULL
#include <stdio.h> 

// --- 1. 내용 기반 가중치 (Content-based) ---
#define WEIGHT_WRITE 5           // 기본 쓰기 5점 
#define WEIGHT_HIGH_ENTROPY 20   // 20점 부여함
#define ENTROPY_THRESHOLD 4.3    //(교수님 자료에 암호화전 읽기/쓰기 상황의 엔트로피가 4.3 이하였던 것에 근거함))

// --- 2. 행위 기반 가중치 (Behavior-based) ---
#define WEIGHT_MALICIOUS 20      // 삭제/변경 20점 (고위험)
#define WEIGHT_MALICIOUS_LOW 2   // 정찰 행위 2점 (저위험)

// --- 3. 맥락 기반 가중치 (Context-based) ---
#define WEIGHT_LARGE_WRITE 150   // 대용량 쓰기 즉시 차단
#define LARGE_WRITE_THRESHOLD (10 * 1024 * 1024) 

// --- 4. 암호화 탐지 가중치 (Entropy-based) ---
#define WEIGHT_RANSOMWARE_DETECTED 150 // 랜섬웨어 탐지 시 즉시 차단
#define ENTROPY_DELTA_THRESHOLD 3.0    // 엔트로피 변화량 기준
#define HIGH_ENTROPY_FLOOR 7.0         // 암호화 의심 기준선 (7.0 이상)



int is_valid_file_header(const char *buf, size_t size) {
    if (size < 4) return 0; 

    // 1. 이미지 (JPG, PNG, GIF, BMP, TIF)
    if (size >= 3 && memcmp(buf, "\xFF\xD8\xFF", 3) == 0) return 1; // JPG
    if (size >= 4 && memcmp(buf, "\x89\x50\x4E\x47", 4) == 0) return 1; // PNG
    if (size >= 6 && (memcmp(buf, "GIF87a", 6) == 0 || memcmp(buf, "GIF89a", 6) == 0)) return 1; // GIF
    if (size >= 2 && memcmp(buf, "BM", 2) == 0) return 1; // BMP
    if (size >= 4 && (memcmp(buf, "II*\x00", 4) == 0 || memcmp(buf, "MM\x00*", 4) == 0)) return 1; // TIF

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

    // 4. 실행 파일 (ELF)
    if (size >= 4 && memcmp(buf, "\x7F\x45\x4C\x46", 4) == 0) return 1;

    return 0; 
}



int get_score(const char* operation, const char* new_buf, const char* old_buf_or_null, size_t size) {
    int score_to_add = 0;

    // --- [1] WRITE (쓰기) 연산 분석 ---
    if (strcmp(operation, "WRITE") == 0) {
        score_to_add += WEIGHT_WRITE; // 기본 5점 부여

        if (new_buf != NULL && size > 0) {
            
            double new_entropy = calculate_entropy(new_buf, size);
            double old_entropy = 0.0;

            if (old_buf_or_null != NULL) {
                old_entropy = calculate_entropy(old_buf_or_null, size);
            }

            double delta = new_entropy - old_entropy;
            
            // [핵심 방어 로직]
            // 조건 1: 변화량이 3.0 이상이거나 (텍스트 -> 암호화 탐지)
            // 조건 2: 결과물이 7.0 이상일 때 (이미지 -> 암호화 탐지)
            if (delta > ENTROPY_DELTA_THRESHOLD || new_entropy > HIGH_ENTROPY_FLOOR) {
                
                // 오탐 방지: "엔트로피는 높지만 헤더가 정상인가?"
                if (is_valid_file_header(new_buf, size)) {
                    // [PASS] 정상 파일(이미지/압축)임.
                } 
                else {
                    // [BLOCK] 헤더가 없거나 깨짐 + 고엔트로피 = 암호화 데이터
                    score_to_add += WEIGHT_RANSOMWARE_DETECTED; // 150점 (즉시 차단)
                }
            }
        }
        
        // [대용량 쓰기 방어]
        if (size > LARGE_WRITE_THRESHOLD) {
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
             strcmp(operation, "GETATTR") == 0 ||
             strcmp(operation, "READDIR") == 0) {
        score_to_add += WEIGHT_MALICIOUS_LOW; // 2점
    
    // --- [4] 기타 조작 행위 ---
    } else if (strcmp(operation, "CREATE") == 0 ||
               strcmp(operation, "MKDIR") == 0 ||
               strcmp(operation, "RMDIR") == 0 ||
               strcmp(operation, "UTIMENS") == 0) {
        score_to_add += WEIGHT_MALICIOUS_LOW; // 2점
    }

    return score_to_add;
}
