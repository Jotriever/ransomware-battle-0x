#ifndef BLACKLIST_H
#define BLACKLIST_H

// 블랙리스트에 파일 경로 추가
int add_to_blacklist(const char *path);

// 블랙리스트에서 파일 경로 제거
int remove_from_blacklist(const char *path);

// 블랙리스트에 있는지 확인
int is_blacklisted(const char *path);

// 블랙리스트 초기화 (기본 항목 추가)
void init_blacklist(void);

// 블랙리스트 메모리 해제
void free_blacklist(void);

// 블랙리스트 항목 수 반환
int get_blacklist_count(void);

#endif // BLACKLIST_H

