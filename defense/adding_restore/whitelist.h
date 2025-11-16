#ifndef WHITELIST_H
#define WHITELIST_H

// 화이트리스트에 경로 추가
int add_to_whitelist(const char *path);

// 해당 파일이 화이트리스트에 등록되어 있는지 확인
int is_writable_whitelisted(const char *path);

// 화이트리스트 메모리 해제
void free_whitelist(void);

// 재귀적으로 디렉토리를 스캔하여 모든 파일을 화이트리스트에 추가
void scan_directory_recursive(const char *base_path, const char *relative_path);

// 화이트리스트 항목 수 반환
int get_whitelist_count(void);

#endif // WHITELIST_H

