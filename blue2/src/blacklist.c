#include "blacklist.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 블랙리스트 목록 구조
static char **blacklist = NULL;
static int blacklist_count = 0;
static int blacklist_capacity = 0;

// 블랙리스트에 파일 경로 추가
int add_to_blacklist(const char *path) {
    // 중복 체크
    for (int i = 0; i < blacklist_count; i++) {
        if (strcmp(path, blacklist[i]) == 0) {
            return 0; // 이미 존재
        }
    }
    
    // 용량 부족 시 확장
    if (blacklist_count >= blacklist_capacity) {
        int new_capacity = blacklist_capacity == 0 ? 10 : blacklist_capacity * 2;
        char **new_list = realloc(blacklist, new_capacity * sizeof(char*));
        if (new_list == NULL) {
            log_message("Error: Failed to allocate memory for blacklist\n");
            return -1;
        }
        blacklist = new_list;
        blacklist_capacity = new_capacity;
    }
    
    // 경로 복사 및 추가
    blacklist[blacklist_count] = strdup(path);
    if (blacklist[blacklist_count] == NULL) {
        log_message("Error: Failed to allocate memory for blacklist entry\n");
        return -1;
    }
    blacklist_count++;
    
    return 0;
}

// 블랙리스트에 있는지 확인 (파일명만 비교)
int is_blacklisted(const char *path) {
    if (!path) return 0;
    
    // 경로에서 파일명만 추출 (마지막 '/' 이후 부분)
    const char *filename = strrchr(path, '/');
    if (filename == NULL) {
        // '/'가 없으면 전체 경로가 파일명
        filename = path;
    } else {
        // '/' 다음 문자부터 시작
        filename++;
    }
    
    // 빈 파일명 체크
    if (filename[0] == '\0') {
        return 0;
    }
    
    // 블랙리스트 항목과 파일명 비교
    for (int i = 0; i < blacklist_count; i++) {
        if (!blacklist[i]) continue;
        
        // 블랙리스트 항목에서도 파일명만 추출 (앞의 '/' 제거)
        const char *blacklist_name = blacklist[i];
        if (blacklist_name[0] == '/') {
            blacklist_name++; // '/' 제거
        }
        
        // 파일명 비교
        if (strcmp(filename, blacklist_name) == 0) {
            return 1; // 블랙리스트에 있음
        }
    }
    return 0; // 블랙리스트에 없음
}

// 블랙리스트 초기화 (기본 항목 추가)
void init_blacklist(void) {
    // 랜섬웨어 이름 목록 (리눅스 기준)
    const char *ransomware_names[] = {
        "/ransomware",
        "/ransomware.exe",
        "/cryptolocker",
        "/cryptowall",
        "/locky",
        "/teslacrypt",
        "/cerber",
        "/wannacry",
        "/petya",
        "/notpetya",
        "/badrabbit",
        "/samsam",
        "/gandcrab",
        "/maze",
        "/sodinokibi",
        "/ryuk",
        "/doppelpaymer",
        "/snatch",
        "/maze",
        "/clop",
        "/conti",
        "/revil",
        "/lockbit",
        "/blackmatter",
        "/alphv",
        "/encrypt",
        "/decrypt",
        "/crypto",
        "/lock",
        "/unlock",
        "/ransom",
        "/encryptor",
        "/decryptor",
        "/cryptor",
        "/locker",
        "/unlocker",
        "/encrypt_file",
        "/decrypt_file",
        "/crypto_file",
        "/lock_file",
        "/unlock_file",
        "/file_encrypt",
        "/file_decrypt",
        "/file_crypto",
        "/file_lock",
        "/file_unlock",
        "/encrypt_all",
        "/decrypt_all",
        "/crypto_all",
        "/lock_all",
        "/unlock_all",
        "/encrypt_files",
        "/decrypt_files",
        "/crypto_files",
        "/lock_files",
        "/unlock_files",
        "/encrypt_data",
        "/decrypt_data",
        "/crypto_data",
        "/lock_data",
        "/unlock_data",
        "/encrypt_disk",
        "/decrypt_disk",
        "/crypto_disk",
        "/lock_disk",
        "/unlock_disk",
        "/encrypt_system",
        "/decrypt_system",
        "/crypto_system",
        "/lock_system",
        "/unlock_system",
        "/encrypt_home",
        "/decrypt_home",
        "/crypto_home",
        "/lock_home",
        "/unlock_home",
        "/encrypt_documents",
        "/decrypt_documents",
        "/crypto_documents",
        "/lock_documents",
        "/unlock_documents",
        "/encrypt_pictures",
        "/decrypt_pictures",
        "/crypto_pictures",
        "/lock_pictures",
        "/unlock_pictures",
        "/encrypt_videos",
        "/decrypt_videos",
        "/crypto_videos",
        "/lock_videos",
        "/unlock_videos",
        "/encrypt_music",
        "/decrypt_music",
        "/crypto_music",
        "/lock_music",
        "/unlock_music",
        "/encrypt_backup",
        "/decrypt_backup",
        "/crypto_backup",
        "/lock_backup",
        "/unlock_backup",
        "/red1",
        "/red2",
        "/red3",
        "/red4",
        "/red5",
        NULL
    };
    
    // 블랙리스트 항목 추가
    for (int i = 0; ransomware_names[i] != NULL; i++) {
        add_to_blacklist(ransomware_names[i]);
    }
    
    log_message("INFO: Blacklist initialized with %d entries\n", blacklist_count);
}

// 블랙리스트 메모리 해제
void free_blacklist(void) {
    if (blacklist != NULL) {
        for (int i = 0; i < blacklist_count; i++) {
            free(blacklist[i]);
        }
        free(blacklist);
        blacklist = NULL;
        blacklist_count = 0;
        blacklist_capacity = 0;
    }
}

// 블랙리스트 항목 수 반환
int get_blacklist_count(void) {
    return blacklist_count;
}

