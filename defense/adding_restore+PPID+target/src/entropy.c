/* entropy.c */
#include "entropy.h" // 함수 선언이 포함된 헤더
#include <math.h>    // log2() 함수 사용
#include <string.h>  // memset() 함수 사용
#include <stddef.h>  // size_t 타입 사용

// 데이터 버퍼의 섀넌 엔트로피(Shannon Entropy)를 계산
// buffer 엔트로피를 계산할 데이터 (바이트 배열)
// size   데이터의 크기 (바이트 수)
// return double 계산된 엔트로피 값

double calculate_entropy(const char *buffer, size_t size) {
    
    // [방어 코드] 데이터 크기가 0이면 계산할 수 없으므로 0.0 반환
    if (size == 0) {
        return 0.0;
    }

    // 1. 바이트별 등장 횟수(빈도) 세기
    long long counts[256];
    memset(counts, 0, sizeof(counts)); // 배열을 0으로 초기화

    for (size_t i = 0; i < size; i++) {
        // (unsigned char)로 변환하여 음수 인덱스 오류 방지
        counts[(unsigned char)buffer[i]]++;
    }

    // 2. 섀넌 엔트로피 공식 적용
    // H(X) = - Σ P(x) * log2(P(x))
    double entropy = 0.0;

    for (int i = 0; i < 256; i++) {
        // 등장하지 않은 바이트는 계산에서 제외 (log2(0)은 정의되지 않음)
        if (counts[i] == 0) {
            continue;
        }

        // 확률 P(x) = (해당 바이트 등장 횟수) / (전체 데이터 크기)
        double probability = (double)counts[i] / size;

        // 공식에 따라 누적
        entropy -= probability * log2(probability);
    }

    return entropy;
}
