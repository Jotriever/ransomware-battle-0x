#ifndef EXTENSION_CHECKER_H
#define EXTENSION_CHECKER_H

// 파일 확장자 추출 함수
const char* get_file_extension(const char *path);

// 랜섬웨어 확장자인지 확인
int is_ransomware_extension(const char *path);

#endif // EXTENSION_CHECKER_H

