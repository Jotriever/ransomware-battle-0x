/* analyzer.c (Final Complete Version) */
#include "entropy.h"
#include "analyzer.h"
#include <string.h> // strcmp, memcmp
#include <stddef.h> // size_t, NULL
#include <stdio.h> 

// --- 1. 내용 기반 가중치 (Content-based) ---
// 기본 쓰기 점수 (5점). '메롱' 같은 미세 변조 반복 공격을 방어 (30회 시 차단)
#define WEIGHT_WRITE 5           

// --- 2. 행위 기반 가중치 (Behavior-based) ---
// 고위험 행위 (삭제, 이름변경). 150/20 = 7.5회. 약 8개 파일 건드리면 차단.
#define WEIGHT_MALICIOUS 20      

// 저위험 정찰 행위 (읽기, 열기, 탐색). 150/2 = 75회. 정상적인 탐색 허용.
#define WEIGHT_MALICIOUS_LOW 2   

// --- 3. 맥락 기반 가중치 (Context-based) ---
// 대용량 쓰기 (DoS/Wiper) 방어. 10MB 넘으면 즉시 차단(150점).
#define WEIGHT_LARGE_WRITE 150   
#define LARGE_WRITE_THRESHOLD (10 * 1024 * 1024) 

// --- 4. 암호화 탐지 가중치 (Entropy-based) ---
// 랜섬웨어 탐지 시 즉시 차단(150점).
#define WEIGHT_RANSOMWARE_DETECTED 150 

// 엔트로피 기준선. 이 값(6.0)을 넘어야만 '암호화 데이터'로 의심하고 검사 시작.
// (텍스트 파일은 보통 4.0 이하기 때문에 이 기준 덕분에 안전함)
#define HIGH_ENTROPY_FLOOR 6.0   


/**
 * @brief 파일 헤더(Magic Number) 검사 함수
 * 고엔트로피 정상 파일(이미지, 압축파일 등)을 랜섬웨어로 오인하는 것을 방지함
 */
int is_valid_file_header(const char *buf, size_t size) {
    if (size < 4) return 0; 

    // 1. 이미지 (JPG, PNG, GIF, BMP, TIF)
    if (size >= 3 && memcmp(buf, "\xFF\xD8\xFF", 3) == 0) return 1; // JPG
    if (size >= 4 && memcmp(buf, "\x89\x50\x4E\x47", 4) == 0) return 1; // PNG
    if (size >= 6 && (memcmp(buf, "GIF87a", 6) == 0 || memcmp(buf, "GIF89a", 6) == 0)) return 1; // GIF
    if (size >= 2 && memcmp(buf, "BM", 2) == 0) return 1; // BMP
    if (size >= 4 && (memcmp(buf, "II*\x00", 4) == 0 || memcmp(buf, "MM\x00*", 4) == 0)) return 1; // TIF

    // 2. 문서 및 압축 (ZIP, Office, APK, JAR) - 가장 중요!
    // docx, xlsx, pptx 등은 모두 'PK'로 시작함
    if (size >= 2 && memcmp(buf, "PK", 2) == 0) return 1;
    
    // PDF (%PDF)
    if (size >= 4 && memcmp(buf, "%PDF", 4) == 0) return 1;
    
    // HWP (한글 OLE 헤더)
    if (size >= 8 && memcmp(buf, "\xD0\xCF\x11\xE0", 4) == 0) return 1;

    // 3. 미디어 (MP4, AVI, MP3)
    if (size >= 12 && memcmp(buf + 4, "ftyp", 4) == 0) return 1; // MP4
    if (size >= 4 && memcmp(buf, "RIFF", 4) == 0) return 1; // AVI, WAV
    if (size >= 3 && memcmp(buf, "ID3", 3) == 0) return 1; // MP3
    if (size >= 2 && (unsigned char)buf[0] == 0xFF && ((unsigned char)buf[1] & 0xE0) == 0xE0) return 1; // MP3 Raw

    // 4. 실행 파일 (ELF)
    if (size >= 4 && memcmp(buf, "\x7F\x45\x4C\x46", 4) == 0) return 1;

    return 0; // 헤더가 없거나 깨짐 (암호화 데이터일 확률 높음)
}


/**
 * @brief FUSE 연산을 분석하여 악성 점수 반환 (Main Logic)
 */
int get_score(const char* operation, const char* new_buf, const char* old_buf_or_null, size_t size) {
    int score_to_add = 0;

    // --- [1] WRITE (쓰기) 연산 분석 ---
    if (strcmp(operation, "WRITE") == 0) {
        score_to_add += WEIGHT_WRITE; // 기본 5점 부여

        if (new_buf != NULL && size > 0) {
            
            // 1. 새로 쓰려는 데이터의 엔트로피 계산
            double new_entropy = calculate_entropy(new_buf, size);
            
            // [핵심 방어 로직]
            // 조건: "지금 쓰려는 데이터가 암호화 수준(6.0 이상)으로 복잡한가?"
            if (new_entropy > HIGH_ENTROPY_FLOOR) {
                
                // 오탐 방지: "복잡하긴 한데, 혹시 정상적인 JPG나 ZIP 파일인가?"
                if (is_valid_file_header(new_buf, size)) {
                    // [PASS] 정상 파일(이미지/압축)임. 점수 부여 안 함.
                } 
                else {
                    // [BLOCK] "엔트로피가 높은데 헤더(신분증)가 없다?"
                    // -> 100% 랜섬웨어 암호화 데이터임.
                    score_to_add += WEIGHT_RANSOMWARE_DETECTED; // 150점 (즉시 차단)
                }
            }
        }
        
        // [대용량 쓰기 방어] (엔트로피와 무관하게 검사)
        // 10MB 이상의 데이터를 한 번에 쓰려고 하면 DoS 공격으로 간주
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
