#ifndef DUMMY_FILE_H
#define DUMMY_FILE_H

// 더미 파일 목록에 추가하는 함수
int add_to_dummy_list(const char *path);

// 더미 파일인지 확인
int is_dummy_file(const char *path);

// 더미 파일 접근 시 프로세스 차단
// 반환값: 0 = 화이트리스트 프로세스 (허용), -1 = 차단됨
int block_process_on_dummy_access(const char *path);

// 더미 파일 목록 메모리 해제
void free_dummy_list(void);

// 더미 파일 항목 수 반환
int get_dummy_file_count(void);

// 더미 파일 경로 반환 (인덱스 기반)
const char* get_dummy_file_path(int index);

#endif // DUMMY_FILE_H

