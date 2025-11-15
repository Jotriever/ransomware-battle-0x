# FUSE 기반 파일시스템 보안 솔루션

## 프로젝트 개요

이 프로젝트는 FUSE(Filesystem in Userspace)를 활용한 파일시스템 보안 솔루션입니다. PID(Process ID) 기반으로 프로세스의 행동을 추적하고, 악성 행동을 감지하여 자동으로 차단하는 시스템입니다.

## 주요 기능

1. **PID 기반 행동 추적**: 각 프로세스의 파일시스템 작업을 추적하고 점수화
2. **악성 행동 감지**: 쓰기, 삭제, 이름 변경 등의 작업을 분석하여 악성 점수 계산
3. **엔트로피 분석**: 쓰기 작업의 데이터 엔트로피를 계산하여 암호화된 데이터 감지
4. **동적 화이트리스트**: 초기화 시점에 백엔드 디렉토리의 모든 파일을 자동으로 화이트리스트에 등록
5. **더미 파일(낚시 파일)**: 랜섬웨어 탐지를 위한 더미 파일 자동 생성 및 접근 시 프로세스 차단
6. **실행 권한 제어**: 화이트리스트에 없는 파일의 실행 권한 제거
7. **자동 차단**: 임계값을 초과한 프로세스 자동 강제 종료

## 파일 구조

### `blue2.c`
메인 FUSE 파일시스템 구현 파일

**주요 기능:**
- FUSE 파일시스템 연산자 구현 (getattr, readdir, open, create, read, write, unlink, rename 등)
- PID별 Malice Score 추적 시스템
- 동적 화이트리스트 시스템
  - 초기화 시점에 백엔드 디렉토리의 모든 파일을 자동으로 화이트리스트에 등록
  - 화이트리스트 파일: 모든 작업 허용 (읽기, 쓰기, 삭제, 실행, 이름변경)
  - 화이트리스트에 없는 파일: 실행만 차단, 나머지 작업 허용
- 더미 파일(낚시 파일) 시스템
  - 프로그램 시작 시 더미 파일 자동 생성
  - 더미 파일 접근 시도 시 프로세스 즉시 강제 종료
- 임계값 초과 시 프로세스 강제 종료 (SIGKILL)

**주요 설정:**
- `MAX_TRACKED_PIDS`: 최대 추적 가능한 PID 개수 (100)
- `KILL_THRESHOLD`: Malice Score 강제 종료 임계값 (80)
- `MAX_WHITELIST_SIZE`: 최대 화이트리스트 항목 수 (10000)
- 백엔드 경로: `$HOME/workspace/target` (고정)
- 더미 파일 목록: `/dummy_secret.txt`, `/important_data.txt`, `/private_key.pem`, `/backup.db`, `/confidential.doc`

### `analyzer.c`
악성 행동 분석 및 점수 계산 모듈

**주요 기능:**
- 파일시스템 작업별 가중치 기반 점수 계산
- 엔트로피 기반 암호화 데이터 감지
- 시간 단위 빈도 분석 (1초 단위)
- 악성 행동 판정

**점수 체계:**
- `WEIGTH_WRITE`: 쓰기 작업 기본 점수 (1점)
- `WEIGTH_MALICIOUS`: UNLINK/RENAME 작업 점수 (3점)
- `WEIGHT_HIGH_ENTROPY`: 높은 엔트로피(4.2 이상) 추가 점수 (5점)
- `ENTROPY_THRESHOLD`: 엔트로피 임계값 (4.2)

**빈도 기반 벌점:**
- `WRITE_THRESHOLE_PER_1`: 1초당 쓰기 임계값 (100회)
- `UNLINK_THRESHOLE_PER_1`: 1초당 삭제 임계값 (10회)
- `RENAME_THRESHOLE_PER_1`: 1초당 이름 변경 임계값 (10회)
- `PENALTY_HIGh_WRITE`: 쓰기 빈도 초과 시 벌점 (50점)
- `PENALTY_HIGh_UNLINK`: 삭제 빈도 초과 시 벌점 (100점)
- `PENALTY_HIGh_RENAME`: 이름 변경 빈도 초과 시 벌점 (100점)

**최종 판정:**
- `FINAL_MALICE_THRESHOLD`: 최종 악성 판정 임계값 (200점)

**주요 함수:**
- `get_score(const char* operation, const char* buf, size_t size)`: 작업별 점수 계산
- `check_frequency_and_alert()`: 빈도 분석 및 악성 판정
- `monitor_operation(const char* operation, const char* buf, size_t size)`: 작업 모니터링

### `analyzer.h`
analyzer.c의 헤더 파일

**함수 선언:**
- `int get_score(const char* operation, const char* buf, size_t size)`

### `entropy.c`
데이터 엔트로피 계산 모듈

**주요 기능:**
- Shannon 엔트로피 공식을 사용한 데이터 분석
- 각 바이트 값의 빈도를 계산하여 데이터의 무작위성 측정
- 암호화된 데이터나 압축된 데이터 감지에 활용

**함수:**
- `double calculate_entropy(const char *buffer, size_t size)`: 버퍼의 엔트로피 값 계산 (0.0 ~ 8.0)

**엔트로피 의미:**
- 낮은 엔트로피 (0.0 ~ 2.0): 반복적인 패턴, 평문 텍스트
- 중간 엔트로피 (2.0 ~ 4.2): 일반적인 데이터
- 높은 엔트로피 (4.2 ~ 8.0): 암호화된 데이터, 압축된 데이터, 랜덤 데이터

### `entropy.h`
entropy.c의 헤더 파일

**함수 선언:**
- `double calculate_entropy(const char*buffer, size_t size)`

## 컴파일 방법

```bash
# 필요한 패키지 설치 (Ubuntu/Debian)
sudo apt-get install libfuse3-dev pkg-config

# Makefile을 사용한 컴파일
make

# 또는 직접 컴파일
gcc -Wall -Wextra -std=c11 -g -D_GNU_SOURCE -Isrc $(pkg-config fuse3 --cflags) \
    src/blue2.c src/analyzer.c src/entropy.c -o blue2 \
    $(pkg-config fuse3 --libs) -lpthread -lm
```

**컴파일 옵션 설명:**
- `-D_GNU_SOURCE`: POSIX 함수 및 상수 사용을 위한 매크로
- `-Isrc`: 소스 디렉토리를 include 경로로 추가
- `pkg-config fuse3 --cflags --libs`: FUSE3 라이브러리 컴파일/링크 옵션
- `-lpthread`: pthread 라이브러리 링크
- `-lm`: 수학 라이브러리 링크 (엔트로피 계산용)

## 실행 방법

1. **백엔드 디렉터리 준비:**
```bash
mkdir -p ~/workspace/target
# 테스트 파일 생성
echo "test" > ~/workspace/target/text.txt
```

2. **마운트 포인트 디렉터리 생성:**
```bash
mkdir -p /tmp/myfs
```

3. **파일시스템 마운트:**
```bash
./blue2 /tmp/myfs
```

4. **사용 예시:**
```bash
# 다른 터미널에서
ls /tmp/myfs
cat /tmp/myfs/text.txt
echo "data" > /tmp/myfs/text.txt  # 화이트리스트 파일: 쓰기 가능
echo "new" > /tmp/myfs/newfile.txt  # 새 파일 생성 가능 (가용성)
rm /tmp/myfs/text.txt             # 화이트리스트 파일: 삭제 가능
mv /tmp/myfs/text.txt /tmp/myfs/new.txt  # 이름 변경 가능
./malware.exe  # 화이트리스트에 없는 파일: 실행 차단
cat /tmp/myfs/dummy_secret.txt  # 더미 파일 접근 시도: 프로세스 즉시 종료
```

5. **언마운트:**
```bash
fusermount -u /tmp/myfs
```

## 보안 메커니즘

### 1. 동적 화이트리스트 시스템
- 프로그램 시작 시 백엔드 디렉토리(`$HOME/workspace/target`)의 모든 파일을 재귀적으로 스캔하여 화이트리스트에 자동 등록
- **화이트리스트 파일**: 모든 작업 허용 (읽기, 쓰기, 삭제, 실행, 이름변경)
- **화이트리스트에 없는 파일**: 실행만 차단, 나머지 작업 허용 (읽기, 쓰기, 삭제, 이름변경, 생성)
- 초기화 시점에 등록된 파일만 화이트리스트에 포함됨
- 추후 정상 파일에 대한 가용성 수정 필요....!!!
### 2. 더미 파일(낚시 파일) 시스템
- 프로그램 시작 시 더미 파일 자동 생성:
  - `/dummy_secret.txt`
  - `/important_data.txt`
  - `/private_key.pem`
  - `/backup.db`
  - `/confidential.doc`
- 더미 파일에 대한 모든 접근 시도 시 프로세스 즉시 강제 종료:
  - 읽기, 쓰기, 삭제, 생성, 이름변경 모두 차단
  - 랜섬웨어가 더미 파일에 접근하면 즉시 탐지 및 차단

### 3. 실행 권한 제어
- 화이트리스트에 없는 파일의 실행 권한 자동 제거
- `getattr` 함수에서 실행 권한 비트(`S_IXUSR`, `S_IXGRP`, `S_IXOTH`) 제거
- 화이트리스트 파일은 실행 권한 유지

### 4. PID 기반 악성 행동 추적
- 각 프로세스별로 Malice Score 추적
- WRITE, UNLINK, RENAME 작업에 점수 부여
- 높은 엔트로피 데이터 감지 시 추가 점수 부여

### 5. 빈도 기반 이상 탐지
- 1초 단위로 작업 빈도 분석
- 임계값 초과 시 추가 벌점 부여

### 6. 자동 차단
- Malice Score가 `KILL_THRESHOLD` (80점) 이상이면 즉시 프로세스 강제 종료
- SIGKILL 신호로 프로세스 종료

## 설정 가능한 값

### `blue2.c`
- `MAX_TRACKED_PIDS`: 최대 추적 PID 수 (기본값: 100)
- `KILL_THRESHOLD`: 강제 종료 임계값 (기본값: 80)
- `MAX_WHITELIST_SIZE`: 최대 화이트리스트 항목 수 (기본값: 10000)
- 동적 화이트리스트: 초기화 시점에 백엔드 디렉토리 스캔하여 자동 등록
- 더미 파일 목록: 프로그램 시작 시 자동 생성 및 등록

### `analyzer.c`
- `WEIGTH_WRITE`: 쓰기 작업 점수 (기본값: 1)
- `WEIGTH_MALICIOUS`: 악성 작업 점수 (기본값: 3)
- `WEIGHT_HIGH_ENTROPY`: 높은 엔트로피 추가 점수 (기본값: 5)
- `ENTROPY_THRESHOLD`: 엔트로피 임계값 (기본값: 4.2)
- `WRITE_THRESHOLE_PER_1`: 1초당 쓰기 임계값 (기본값: 100)
- `UNLINK_THRESHOLE_PER_1`: 1초당 삭제 임계값 (기본값: 10)
- `RENAME_THRESHOLE_PER_1`: 1초당 이름 변경 임계값 (기본값: 10)
- `PENALTY_HIGh_WRITE`: 쓰기 빈도 초과 벌점 (기본값: 50)
- `PENALTY_HIGh_UNLINK`: 삭제 빈도 초과 벌점 (기본값: 100)
- `PENALTY_HIGh_RENAME`: 이름 변경 빈도 초과 벌점 (기본값: 100)
- `FINAL_MALICE_THRESHOLD`: 최종 악성 판정 임계값 (기본값: 200)

## 주의사항

1. **환경 변수**: `HOME` 환경 변수가 설정되어 있어야 합니다.
2. **백엔드 경로**: `$HOME/workspace/target` 디렉터리가 존재해야 합니다.
3. **권한**: FUSE 파일시스템 마운트는 적절한 권한이 필요합니다.
4. **디버깅**: `stderr`에 로그가 출력되므로 디버깅 시 확인하세요.

## 알려진 제한사항

1. **저엔트로피 우회**: 반복적인 패턴을 사용하면 엔트로피 기반 감지를 우회할 수 있습니다.
2. **PID 기반 추적**: PID는 실행마다 재생성되므로, 프로세스 이름 기반 추적이 더 효과적일 수 있습니다.
3. **화이트리스트 고정**: 초기화 시점에 등록된 파일만 화이트리스트에 포함되며, 런타임에 추가된 파일은 포함되지 않습니다.

## 접근 제어 정책

### 화이트리스트 파일
- **모든 작업 허용**: 읽기, 쓰기, 삭제, 실행, 이름변경 모두 가능
- 초기화 시점에 백엔드 디렉토리에 존재하던 파일만 포함

### 화이트리스트에 없는 파일
- **실행만 차단**: 실행 권한 제거
- **나머지 작업 허용**: 읽기, 쓰기, 삭제, 이름변경, 생성 모두 가능
- 가용성을 위해 정상 사용자/프로그램의 작업을 방해하지 않음

### 더미 파일(낚시 파일)
- **모든 접근 차단**: 읽기, 쓰기, 삭제, 생성, 이름변경 모두 차단
- **프로세스 즉시 종료**: 더미 파일 접근 시도 시 프로세스 강제 종료
- 랜섬웨어 탐지 및 차단 목적

## 향후 개선 방향

1. 프로세스 이름 기반 추적 추가
2. 런타임 화이트리스트 동적 업데이트 기능
3. 파일 해시 기반 검증 시스템
4. 더 정교한 엔트로피 분석 알고리즘
5. 실시간 로깅 및 모니터링 시스템
6. 더미 파일 목록 커스터마이징 기능


