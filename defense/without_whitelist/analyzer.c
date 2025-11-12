/* analyzer.c (최종 수정본) */
#include "entropy.h"
#include "analyzer.h"
#include <string.h> // strcmp 함수
#include <stddef.h> // size_t, NULL
#include <stdio.h> 

// 1. 내용 기반
#define WEIGHT_WRITE 1
#define WEIGHT_HIGH_ENTROPY 20
#define ENTROPY_THRESHOLD 4.2

// 2. 행위 기반
#define WEIGHT_MALICIOUS 10 // (고위험)
#define WEIGHT_MALICIOUS_LOW 2 // (저위험군이긴 하나, 정찰 행위를 누적해서 할 경우 대비)

// 3. 맥락 기반
#define WEIGHT_LARGE_WRITE 150
#define LARGE_WRITE_THRESHOLD (10* 1024 * 1024)

// 4. 변화량 기반
#define WEIGHT_DELTA_ENTROPY 150 // 엔트로피가 3.0 이상 변화시 150점 부가
#define ENTROPY_DELTA_THRESHOLD 3.0 // 엔트로피 변화량의 임계값
#define HIGH_ENTROPY_FLOOR 6.0 // 일반 텍스트는 4.5 를 넘기기 어려우므로, 빈파일에 대해 쓰기를 시도해도 악성이라고 판단하지 않음

//(12일 과제) 변경사항 * new_buf == 파일에 새로 쓰려는 데이터, old_buf == 기존에 있던 원본데이터를 의미
int get_score(const char* operation, const char* new_buf, const char* old_buf_or_null, size_t size) {
    int score_to_add = 0;

    if (strcmp(operation, "WRITE") == 0) {
        score_to_add += WEIGHT_WRITE;

        if (new_buf != NULL && size > 0) {
            double new_entropy = calculate_entropy(new_buf, size);
            double old_entropy = 0.0; // 파일이 생성되는 경우에는 원본데이터 == 0

            if (old_buf_or_null != NULL) {
                old_entropy = calculate_entropy(old_buf_or_null, size); // 파일을 생성하는 경우가 아니면 기존 엔트로피를 계산
            }

            double delta = new_entropy - old_entropy;
            
            // [오탐 방지 수정]
            // (변화량이 3.0을 넘고) "그리고" (새 엔트로피가 6.0을 넘을 때) 무조건 악성으로 판단
	    // && 구문을 안 쓰면 짧은 문장을 입력(echo) 하는 상황에서 악성으로 판단해버림
            if (delta > ENTROPY_DELTA_THRESHOLD && new_entropy > HIGH_ENTROPY_FLOOR) {
                score_to_add += WEIGHT_DELTA_ENTROPY; 
            }
        }
	// 동일 문자 입력으로 저엔트로피 우회하는 걸 막기 위해 한 번에 10MB 쓰기를 진행하면 무조건 악성으로 판단
        if (size > LARGE_WRITE_THRESHOLD) {
            score_to_add += WEIGHT_LARGE_WRITE;
        }
    //삭제, 이름변경 시 10점 부여(고위험)
    } else if (strcmp(operation, "UNLINK") == 0 || strcmp(operation, "RENAME") == 0) {
        score_to_add += WEIGHT_MALICIOUS;
   //나머지 행위들에 대해 2점 부여(저위험) -> 이 행위들에 대해 가중치를 높여버리면 너무 쉽게 점수가 누적돼서 함부로 건드리기 애매함..
    } else if (strcmp(operation, "READ") == 0 ||
               strcmp(operation, "OPEN") == 0 ||
               strcmp(operation, "GETATTR") == 0 ||
               strcmp(operation, "READDIR") == 0) {
        score_to_add += WEIGHT_MALICIOUS_LOW;
    
    } else if (strcmp(operation, "CREATE") == 0 ||
               strcmp(operation, "MKDIR") == 0 ||
               strcmp(operation, "RMDIR") == 0 ||
               strcmp(operation, "UTIMENS") == 0) {
        score_to_add += WEIGHT_MALICIOUS_LOW;
    }

    return score_to_add;  // 모든 행위들에 대한 누적된 점수 반환
}
