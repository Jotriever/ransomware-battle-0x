
#include "entropy.h"
#include "analyzer.h"
#include <string.h> // strcmp, memcmp
#include <stddef.h> // size_t, NULL
#include <stdio.h> 

// --- 1. 가중치 설정 (Weight Configuration) ---/

// --- 1. 내용 기반 (Content-based) ---
// [상향] 기본 쓰기 점수를 5배 높임.
// 효과: '메롱' 덮어쓰기 같은 미세한 파괴 행위도 30번(150/5) 만에 차단됨.
#define WEIGHT_WRITE 5           //쓰기 행위 시 
#define WEIGHT_HIGH_ENTROPY 20   // 20점 부여함
#define ENTROPY_THRESHOLD 4.3 //엔트로피가 4.3 보다 높으면 (교수님 자료에 암호화전 읽기/쓰기 상황의 엔트로피가 4.3 이하였던 것
에 근거함))

// --- 2. 행위 기반 (Behavior-based) ---
// [상향] 삭제/변경 점수를 2배 높임.
// 효과: 파일을 8개만 삭제(unlink)하거나 암호화 후 이름 변경(rename)해도 즉시 차단됨.
#define WEIGHT_MALICIOUS 20      

// [유지]평소에 자주하는 정찰 행위인 파일을 읽거나(read), 정보를 보는 것(getattr)은 너무 높이면 'ls' 명령어도 막히므로 2점 유>지
#define WEIGHT_MALICIOUS_LOW 2   

// --- 3. 맥락 기반 (Context-based) ---
// [유지] 한 방 차단 (임계치와 동일하게 설정)
#define WEIGHT_LARGE_WRITE 150   //150점 바로 부여
#define LARGE_WRITE_THRESHOLD (10 * 1024 * 1024) //10MB 넘게 쓰면

//고엔트로피 정상 파일(이미지, 압축파일 등)을 랜섬웨어로 오인하는 것을 방지함
int is_valid_file_header(const char *buf, size_t size) {
    if (size < 4) return 0; 

    // 1. 이미지 (JPG, PNG, GIF, BMP, TIF)
    if (size >= 3 && memcmp(buf, "\xFF\xD8\xFF", 3) == 0) return 1; // JPG
    if (size >= 4 && memcmp(buf, "\x89\x50\x4E\x47", 4) == 0) return 1; // PNG
    if (size >= 6 && (memcmp(buf, "GIF87a", 6) == 0 || memcmp(buf, "GIF89a", 6) == 0)) return 1; // GIF
    if (size >= 2 && memcmp(buf, "BM", 2) == 0) return 1; // BMP
    if (size >= 4 && (memcmp(buf, "II*\x00", 4) == 0 || memcmp(buf, "MM\x00*", 4) == 0)) return 1; // TIF림
int get_score(const char* operation, const char* new_buf, const char* old_buf_or_null, size_t size) {
    int score_to_add = 0;

    // --- [1] WRITE (쓰기) 연산 분석 ---
    if (strcmp(operation, "WRITE") == 0) {
        score_to_add += WEIGHT_WRITE; // 기본 5점 부여

        if (new_buf != NULL && size > 0) {
            
            // 1. 새로 쓰려는 데이터의 엔트로피 계산
            double new_entropy = calculate_entropy(new_buf, size);
            
            // [수정된 핵심 로직] 
            // Delta(변화량) 조건은 삭제했습니다. (텍스트 파일 오탐 방지)
            // 오직 "결과물이 암호화 데이터(7.0 이상)인가?"만 확인합니다.
            if (new_entropy > HIGH_ENTROPY_FLOOR) {
                
                // 7.0이 넘는 고엔트로피 데이터라면, 정상 파일(JPG, ZIP)인지 신분증 검사
                if (is_valid_file_header(new_buf, size)) {
                    // [PASS] 정상 파일임. 점수 부여 안 함.
                } 
                else {
                    // [BLOCK] 엔트로피는 높은데 신분증이 없다 -> 랜섬웨어!
                    score_to_add += WEIGHT_RANSOMWARE_DETECTED; // 150점 (즉시 차단)
                }
            }
        }
        
        // [대용량 쓰기 방어] (엔트로피와 무관하게 검사)
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
