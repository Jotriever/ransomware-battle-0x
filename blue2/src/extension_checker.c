#include <string.h>
#include <strings.h>  // strcasecmp를 위한 헤더
#include "extension_checker.h"
#include "logger.h"

// 랜섬웨어 확장자 목록
static const char *ransomware_extensions[] = {
    ".encrypted",
    ".locked",
    ".crypto",
    ".vault",
    ".ecc",
    ".ezz",
    ".exx",
    ".zzz",
    ".xyz",
    ".aaa",
    ".micro",
    ".encryptedRSA",
    ".crinf",
    ".r5a",
    ".XRNT",
    ".XTBL",
    ".crypt",
    ".R16M01D05",
    ".pzdc",
    ".good",
    ".LOL!",
    ".OMG!",
    ".RDM",
    ".RRK",
    ".vscrypt",
    ".hydra",
    ".locky",
    ".zepto",
    ".odin",
    ".shit",
    ".xxx",
    ".abc",
    NULL
};

// 파일 확장자 추출 함수
const char* get_file_extension(const char *path) {
    const char *dot = strrchr(path, '.');
    if (dot == NULL || dot == path) {
        return NULL; // 확장자가 없거나 숨김 파일
    }
    return dot; // '.' 포함한 확장자 반환
}

// 랜섬웨어 확장자인지 확인
int is_ransomware_extension(const char *path) {
    const char *ext = get_file_extension(path);
    if (ext == NULL) {
        return 0;
    }
    
    for (int i = 0; ransomware_extensions[i] != NULL; i++) {
        if (strcasecmp(ext, ransomware_extensions[i]) == 0) {
            // 랜섬웨어 확장자 발견 시 로깅
            log_message("INFO: 랜섬웨어 확장자 감지: %s (확장자: %s)\n", path, ext);
            return 1; // 랜섬웨어 확장자 발견
        }
    }
    return 0;
}

