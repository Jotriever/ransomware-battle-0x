# 랜섬웨어 방어 시스템 - 행위 기반 필터링 재귀적 하향 Kill

## 개요

이 시스템은 **행위 기반 필터링(Behavior-based Filtering)**을 통한 재귀적 하향 kill 메커니즘을 구현하여, 랜섬웨어 프로세스를 정확하게 타겟팅하면서도 정상 프로세스(bash, sshd, systemd 등)를 보호합니다.

## 핵심 기능

### 1. 행위 기반 필터링 (Behavior-based Filtering)

단순히 프로세스 트리 구조만으로 kill하는 것이 아니라, **실제 악의적 행위를 한 프로세스만** 선별하여 kill합니다.

- **더미 파일 접근 이력**: 더미 파일(낚시 파일)에 접근한 프로세스 추적
- **랜섬웨어 확장자 사용**: 알려진 랜섬웨어 확장자(.encrypted, .locked 등) 사용 이력 추적
- **Malice Score**: 프로세스의 악의적 행위 점수 추적

### 2. 재귀적 하향 Kill (Recursive Downward Kill)

Root 프로세스에서 kill이 실패할 경우(권한 문제 등), 한 단계씩 아래로 내려가며 악의적 행위를 한 프로세스를 찾아 kill합니다.

```
Root Process (kill 실패)
  ↓
Child Process 1 (악의적 행위 없음 → 자식 확인)
  ↓
Child Process 2 (악의적 행위 있음 → kill 성공!)
```

### 3. 정상 프로세스 보호 (Whitelist Protection)

화이트리스트에 등록된 정상 프로세스는 **절대 kill하지 않습니다**. 이들은 건드리지 않고 자식 프로세스만 확인합니다.

## 구현 상세

### ProcessScore 구조체 확장

```c
typedef struct {
    pid_t pid;             
    int malice_score;      
    time_t last_write_time;
    char proc_name[32];
    int has_dummy_access;      // 더미 파일 접근 이력
    int has_ransomware_ext;    // 랜섬웨어 확장자 사용 이력
} ProcessScore;
```

### 주요 함수

#### `kill_malicious_tree_recursive(pid_t target_pid, int depth)`

재귀적 하향 kill의 핵심 함수입니다.

**동작 순서:**
1. **깊이 제한 체크**: 최대 10단계까지만 재귀 (무한 재귀 방지)
2. **프로세스 존재 확인**: `/proc/[pid]` 디렉토리 확인
3. **화이트리스트 체크**: 정상 프로세스면 자식만 확인하고 건드리지 않음
4. **악의적 행위 확인**:
   - `malice_score > 0`
   - `has_dummy_access == 1`
   - `has_ransomware_ext == 1`
5. **Kill 시도**: 프로세스 그룹 단위 kill → 실패 시 개별 kill
6. **재귀적 처리**: Kill 실패 시 자식 프로세스로 재귀

#### `is_whitelisted_process(pid_t pid)`

프로세스가 화이트리스트에 있는지 확인합니다.

**보호되는 프로세스:**
- **쉘**: bash, sh, zsh, fish, dash, csh, tcsh
- **시스템**: sshd, systemd, init, systemd-logind
- **에디터**: vim, vi, nano, emacs
- **개발 도구**: python, gcc, make, cmake
- **유틸리티**: ls, cat, grep, find, ps, top, htop
- **FUSE 파일시스템**: blue2

#### `set_dummy_access_flag(pid_t pid)`

더미 파일 접근 시 호출되어 해당 프로세스의 플래그를 설정합니다.

#### `set_ransomware_ext_flag(pid_t pid)`

랜섬웨어 확장자 사용 시 호출되어 해당 프로세스의 플래그를 설정합니다.

#### `find_direct_children(pid_t ppid, pid_t *children, int max_children)`

특정 프로세스의 직접 자식 프로세스들을 찾습니다.

## 동작 시나리오

### 시나리오 1: 더미 파일 접근 감지

```
1. 랜섬웨어가 /dummy_secret.txt 접근
2. block_process_on_dummy_access() 호출
3. set_dummy_access_flag(current_pid) 설정
4. 루트 부모 프로세스 찾기
5. kill_malicious_tree_recursive(root_ppid, 0) 호출
6. 각 프로세스마다:
   - 화이트리스트 체크 → 정상 프로세스(bash, sshd)는 건드리지 않음
   - 악의적 행위 확인 → 더미 파일 접근 이력 있는 프로세스 kill
   - Kill 실패 시 → 자식 프로세스로 재귀
```

### 시나리오 2: 랜섬웨어 확장자 사용

```
1. 랜섬웨어가 .encrypted 확장자로 파일 생성
2. myfs_create()에서 is_ransomware_extension() 감지
3. set_ransomware_ext_flag(current_pid) 설정
4. 프로세스 kill 시도
5. Kill 실패 시 → 재귀적 하향 kill로 처리
```

## 프로세스 트리 예시

```
sshd (PID 1793) [화이트리스트 - 보호됨]
  └─ bash (PID 2000) [화이트리스트 - 보호됨]
      └─ ./ransomware (PID 2148) [악의적 행위 - kill 대상]
          └─ child1 (PID 2149) [악의적 행위 - kill 대상]
          └─ child2 (PID 2150) [악의적 행위 - kill 대상]
```

**처리 결과:**
- `sshd`, `bash`: 화이트리스트에 있어 건드리지 않음
- `./ransomware`, `child1`, `child2`: 악의적 행위가 있어 kill됨
- 사용자의 터미널 세션은 유지됨

## 장점

### 1. 정확한 타겟팅
- 실제 악의적 행위를 한 프로세스만 kill
- 이름이 뭐든 상관없이 행위로 판단

### 2. 정상 프로세스 보호
- bash, sshd 등 정상 프로세스는 절대 kill하지 않음
- 시스템 마비 없이 방어 가능

### 3. Root 우회
- Root 프로세스에서 kill 실패해도 자식 프로세스로 내려가며 kill 가능
- 권한 문제를 우회하여 악의 프로세스 제거

### 4. 자폭 방지
- 방어 시스템이 정상 프로세스를 kill하여 시스템이 마비되는 것을 방지

### 5. 재귀적 처리
- Kill 실패 시 자동으로 자식 프로세스로 내려가며 kill 시도
- 프로세스 트리 전체를 효율적으로 탐색

## 제한사항

1. **깊이 제한**: 최대 10단계까지만 재귀 (무한 재귀 방지)
2. **프로세스 그룹**: 같은 프로세스 그룹의 다른 프로세스도 kill될 수 있음
3. **타이밍**: 프로세스가 재귀 중에 종료되거나 새로 생성될 수 있음

## 컴파일 및 실행

```bash
cd ransonware-battle/defense/final_version+PGID_KILL
make clean
make
./blue2 <mountpoint>
```

## 로그 확인

로그 파일 위치: `~/workspace/ransomware_defense.log`

주요 로그 메시지:
- `INFO: 화이트리스트 프로세스 보호 (PID=xxx, name=xxx)`
- `INFO: 악의적 행위 감지 (PID=xxx, name=xxx, score=xxx, dummy=xxx, ransom=xxx)`
- `✅ 프로세스 그룹 kill 성공 (PGID=xxx, PID=xxx)`
- `❌ 프로세스 그룹 kill 실패 (PGID=xxx): Operation not permitted`

## 파일 구조

```
final_version+PGID_KILL/
├── src/
│   ├── process_tracker.c    # 재귀적 하향 kill 구현
│   ├── process_tracker.h    # 함수 선언 및 구조체 정의
│   ├── dummy_file.c         # 더미 파일 접근 처리
│   ├── blue2.c              # FUSE 파일시스템 메인
│   └── ...
├── Makefile
└── README.md
```

## 참고사항

- 이 시스템은 **행위 기반 필터링**을 통해 정확한 타겟팅을 수행합니다.
- 화이트리스트 프로세스는 **절대 kill하지 않습니다**.
- Root 프로세스에서 kill 실패 시 **자동으로 자식 프로세스로 내려가며** kill을 시도합니다.
- 모든 kill 시도는 로그에 기록됩니다.

