#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define BUFFER_SIZE 4096

// Base64 인코딩 테이블
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * @brief Base64 인코딩 함수
 * @param input 입력 데이터
 * @param input_len 입력 데이터 길이
 * @param output 출력 버퍼 (충분히 크게 할당되어야 함)
 * @return 인코딩된 문자열 길이
 */
static size_t base64_encode(const unsigned char *input, size_t input_len, char *output) {
    size_t i, j;
    uint32_t a, b, c;
    
    for (i = 0, j = 0; i < input_len;) {
        a = i < input_len ? input[i++] : 0;
        b = i < input_len ? input[i++] : 0;
        c = i < input_len ? input[i++] : 0;
        
        uint32_t bitmap = (a << 16) | (b << 8) | c;
        
        output[j++] = base64_table[(bitmap >> 18) & 63];
        output[j++] = base64_table[(bitmap >> 12) & 63];
        output[j++] = (i - 2) < input_len ? base64_table[(bitmap >> 6) & 63] : '=';
        output[j++] = (i - 1) < input_len ? base64_table[bitmap & 63] : '=';
    }
    
    output[j] = '\0';
    return j;
}

/**
 * @brief Base64 디코딩 함수
 * @param input 입력 Base64 문자열
 * @param input_len 입력 문자열 길이
 * @param output 출력 버퍼
 * @return 디코딩된 데이터 길이, 실패 시 -1
 */
static int base64_decode(const char *input, size_t input_len, unsigned char *output) {
    size_t i, j;
    int a, b, c, d;
    int padding = 0;
    
    // Base64 문자를 인덱스로 변환하는 테이블
    static int base64_reverse[256];
    static int table_initialized = 0;
    
    if (!table_initialized) {
        memset(base64_reverse, -1, sizeof(base64_reverse));
        for (i = 0; i < 64; i++) {
            base64_reverse[(unsigned char)base64_table[i]] = (int)i;
        }
        table_initialized = 1;
    }
    
    // 패딩 계산
    if (input_len > 0 && input[input_len - 1] == '=') {
        padding++;
        if (input_len > 1 && input[input_len - 2] == '=') {
            padding++;
        }
    }
    
    for (i = 0, j = 0; i < input_len; i += 4) {
        a = (i < input_len && input[i] != '=') ? base64_reverse[(unsigned char)input[i]] : 0;
        b = (i + 1 < input_len && input[i + 1] != '=') ? base64_reverse[(unsigned char)input[i + 1]] : 0;
        c = (i + 2 < input_len && input[i + 2] != '=') ? base64_reverse[(unsigned char)input[i + 2]] : 0;
        d = (i + 3 < input_len && input[i + 3] != '=') ? base64_reverse[(unsigned char)input[i + 3]] : 0;
        
        if (a == -1 || b == -1 || c == -1 || d == -1) {
            return -1; // 잘못된 Base64 문자
        }
        
        uint32_t bitmap = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        
        output[j++] = (bitmap >> 16) & 0xFF;
        if (i + 2 < input_len && input[i + 2] != '=') {
            output[j++] = (bitmap >> 8) & 0xFF;
        }
        if (i + 3 < input_len && input[i + 3] != '=') {
            output[j++] = bitmap & 0xFF;
        }
    }
    
    return (int)j;
}

/**
 * @brief Base64 인코딩을 사용해 파일을 인코딩
 */
int encrypt_file_base64(const char *input_file, const char *output_file) {
    FILE *in_file, *out_file;
    unsigned char in_buf[BUFFER_SIZE];
    char out_buf[BUFFER_SIZE * 4 / 3 + 4]; // Base64는 약 4/3배 크기 증가
    size_t in_len;
    size_t out_len;
    
    // 파일 열기
    in_file = fopen(input_file, "rb");
    if (!in_file) {
        perror("fopen (input)");
        return -1;
    }
    
    out_file = fopen(output_file, "wb");
    if (!out_file) {
        perror("fopen (output)");
        fclose(in_file);
        return -1;
    }
    
    // 파일 읽기 -> Base64 인코딩 -> 인코딩된 데이터 쓰기
    while ((in_len = fread(in_buf, 1, BUFFER_SIZE, in_file)) > 0) {
        out_len = base64_encode(in_buf, in_len, out_buf);
        if (fwrite(out_buf, 1, out_len, out_file) != out_len) {
            perror("fwrite");
            fclose(in_file);
            fclose(out_file);
            return -1;
        }
    }
    
    fclose(in_file);
    fclose(out_file);
    return 0;
}

/**
 * @brief Base64 디코딩을 사용해 파일을 디코딩
 */
int decrypt_file_base64(const char *input_file, const char *output_file) {
    FILE *in_file, *out_file;
    char in_buf[BUFFER_SIZE * 4 / 3 + 4];
    unsigned char out_buf[BUFFER_SIZE];
    size_t in_len;
    int out_len;
    
    // 파일 열기
    in_file = fopen(input_file, "rb");
    if (!in_file) {
        perror("fopen (input)");
        return -1;
    }
    
    out_file = fopen(output_file, "wb");
    if (!out_file) {
        perror("fopen (output)");
        fclose(in_file);
        return -1;
    }
    
    // 파일 읽기 -> Base64 디코딩 -> 디코딩된 데이터 쓰기
    while ((in_len = fread(in_buf, 1, sizeof(in_buf), in_file)) > 0) {
        // 개행 문자 제거
        size_t clean_len = 0;
        for (size_t i = 0; i < in_len; i++) {
            if (in_buf[i] != '\n' && in_buf[i] != '\r') {
                in_buf[clean_len++] = in_buf[i];
            }
        }
        
        if (clean_len > 0) {
            out_len = base64_decode(in_buf, clean_len, out_buf);
            if (out_len < 0) {
                fprintf(stderr, "Error: Invalid Base64 data\n");
                fclose(in_file);
                fclose(out_file);
                return -1;
            }
            
            if (fwrite(out_buf, 1, out_len, out_file) != (size_t)out_len) {
                perror("fwrite");
                fclose(in_file);
                fclose(out_file);
                return -1;
            }
        }
    }
    
    fclose(in_file);
    fclose(out_file);
    return 0;
}

