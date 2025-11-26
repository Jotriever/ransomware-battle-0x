
# 🔐 Blue2 Anti-Ransomware Defense  
실시간 랜섬웨어 탐지 · PID/PPID 행위 분석 · CoW 기반 자동 복구 시스템

본 프로젝트는 FUSE 기반 사용자 수준 파일 시스템을 활용해  
**실시간 랜섬웨어 공격 탐지 및 자동 복구를 수행하는 고급형 방어 시스템**이다.

본 README에서 설명할 부분은

1) **Analyzer 기반 행위 스코어링**  
2) **PID/PPID 이중 행위 기반 탐지 엔진**  
3) **Copy-on-Write(CoW) 기반 Restore 모듈**

본 README에서 전체 구조와 구현한 주요 기능, 설계 의도 및 개선 포인트를 정리

# 0. 행위기반 탐지
## 🚀 주요 기능 및 특징

* **실시간 행위 분석:** 모든 파일 접근(`OPEN`, `READ`, `WRITE`, `UNLINK` 등)을 가로채어 점수화
* **엔트로피 변화량 탐지:** 파일이 암호화되어 무작위성(Entropy)이 급증하는 순간을 포착
* **매직 넘버(Magic Number) 검사:** JPG, ZIP, PDF 등 정상적인 고엔트로피 파일을 랜섬웨어로 오인하는 오탐(False Positive)을 방지
* **DoS/Wiper 방어:** 10MB 이상의 대용량 쓰기 시도를 탐지하여 즉시 차단
* **능동적 방어 (Active Defense):** 악성 행위가 임계치를 초과하면 해당 프로세스에 `SIGKILL`을 전송하여 강제 종료

---

## 🛠️ 시스템 아키텍처

 크게 **분석(Analysis)** 계층과 **집행(Enforcement)** 계층으로 분류

### 1. `analyzer.c`: 탐지 및 분석
파일 연산의 위험도를 계산하는 핵심 모듈

* **내용 기반 탐지:**
    * **엔트로피 분석:**`entropy.c`의 함수를 호출**하여 ** `calculate_entropy()`를 통해 데이터의 무작위성을 측정
    * **방어 로직:** `(엔트로피 > 7.0) AND (헤더 없음)` → **암호화 공격**으로 간주하여 **즉시 차단 (150점)**.
* **맥락 기반 탐지:**
    * **대용량 쓰기:** 단일 `write` 요청이 **10MB**를 초과하면 **즉시 차단 (150점)**.
* **행위 기반 탐지:**
    * **고위험군 (삭제/변경):** 20점 부여 (약 7~8회 반복 시 차단).
    * **저위험군 (정찰/탐색):** 2점 부여 (정상적인 탐색은 허용하되, 과도한 스캔 시 차단).

### 2. `blue2.c` : FUSE 시스템
분석 결과에 따라 실제 차단을 수행하는 모듈
* **PID 상태 추적:** 프로세스 ID(PID)별로 악성 점수(`Malice Score`)를 누적 관리
* **차단 집행:** 누적 점수가 임계치(`KILL_THRESHOLD = 150`)를 넘으면 `kill()` 함수를 호출

---

## ⚙️ 보안 정책 (Threshold & Weights)

공격 유형별 대응 전략은 다음과 같음. (임계치: **150점**)

| 공격 유형 | 가중치/점수 | 탐지 로직 | 차단 시점 |
| :--- | :--- | :--- | :--- |
| **랜섬웨어 (암호화)** | **150점** | `Entropy > 7.0` & `Invalid Header` | **즉시 차단 (1회)** |
| **데이터 폭탄 (Wiper)** | **150점** | `Size > 10MB` | **즉시 차단 (1회)** |
| **파일 삭제/변조** | **20점** | `UNLINK`, `RENAME` | **약 8회 반복 시** |
| **미세 변조 (Overwrite)** | **5점** | `WRITE` (Low Entropy) | **30회 반복 시** |
| **사전 정찰 (Scan)** | **2점** | `READ`, `OPEN`, `GETATTR` | **75회 반복 시** |

---

---

# 1. Process Tracker (PID/PPID 기반 이중 탐지 엔진)

본 파일은 **PID + PPID 기반 이중 행위 분석 구조**이다.

랜섬웨어가 **병렬(child 프로세스)**로 파일을 암호화하여 pid기반 점수체계를 회피하는 것을 방지하기 위해 PPID 그룹 점수 개념을 도입.

---

## 1-1. PID 기반 프로세스 점수 관리

```c
typedef struct {
    pid_t pid;
    int malice_score;
    time_t last_write_time;
    char proc_name[32];
} ProcessScore;
```

특징:

- 각 프로세스는 고유한 점수를 가짐  
- 점수는 Analyzer가 부여  
- 마지막 WRITE 시각(last_write_time)을 기록하여  
  “짧은 시간 내 집중적인 연속 WRITE” 패턴 탐지 가능  
  :contentReference[oaicite:0]{index=0}

PID 엔트리는 다음 함수로 생성·조회된다:

```c
static ProcessScore* find_or_create_score_entry(pid_t pid)
```
:contentReference[oaicite:1]{index=1}

이 함수는 O(1)에 가까운 속도로 PID 테이블 접근을 제공하여  
FUSE I/O 성능 저하를 최소화한다.

---

## 1-2. PPID 기반 그룹 점수 관리 (멀티프로세싱 공격 대응)

```c
typedef struct {
    pid_t ppid;
    int group_score;
} PpidGroup;
```
:contentReference[oaicite:2]{index=2}

특징:

- 동일한 부모 프로세스(PPID)를 가진 모든 child들의 점수가 누적됨  
- 랜섬웨어가 병렬로 파일을 암호화하더라도  
  **그룹 전체 점수가 빠르게 상승**하여 즉시 차단 가능

update 방식:

```c
pid_t ppid = get_ppid_of(pid);
update_group_score(ppid, added_score);

if (get_group_score(ppid) >= KILL_THRESHOLD) {
    restore_backup_file(path, base_fd);
    kill(pid, SIGKILL);
    return -EIO;
}
```
:contentReference[oaicite:3]{index=3}

### ✔ 구현 효과

- 단일 공격자 → PID 점수로 탐지  
- 병렬 공격자 → PPID 그룹 점수로 탐지  
- **현실 랜섬웨어 공격 패턴을 반영**

---

# 2. Restore Module – Copy-on-Write(CoW) 기반 자동 백업·복구

Restore는 본 프로젝트의 **두 번째 핵심 기능**이다.

초기 설계에서는 “모든 파일을 실행 시작 시 즉시 백업”하려 했지만,  
다음 문제를 발견했다:

- 보호 디렉터리 1GB → 백업본도 1GB 필요 (용량 2배)  
- 초기 백업 시간 과도함  
- 대부분의 파일이 공격받지 않음 (불필요한 백업)

따라서 운영체제의 **Copy-on-Write(CoW)** 개념을 도입했다.

---

## 2-1. CoW 백업 – “쓰기(WRITE) 발생 시에만” 원본 백업

```c
restore_backup_on_write(path, base_fd);
```


특징:

- WRITE가 발생한 파일만 백업  
- 변경되지 않은 파일은 백업하지 않음  
- I/O 부하 및 용량 문제 해결

---

## 2-2. 복구는 WRITE / CREATE / UNLINK / RENAME에서만 수행

불필요한 복구·백업을 모두 제거하여 성능 최적화.

복구 대상 이벤트: WRITE, CREATE, UNLINK, RENAME
임계치를 넘어 프로세스가 강제 종료 되기 전에 복구해
강제종료가 되지 않아 계속 복구가 불가능한 상황 방지

WRITE에만 백업하고,  
위 4개 연산에서만 복구를 수행하여  
**비용을 최소화하는 설계**이다.

---

## 2-3. Restore module 주요 함수 설명

### ✔ restore_init()
- 백업 디렉터리 생성 (`~/workspace/restore_backup`)  
- realpath 변환  
- 존재하지 않으면 mkdir + 권한 700  
- 공격자가 접근하지 못하도록 보호  


### ✔ restore_backup_on_write()
- 이미 백업본 존재하면 PASS  
- 원본 파일을 openat()으로 열어 백업본 생성  
- 4096byte 단위로 안전하게 copy  


### ✔ copy_file_data()
- 파일 복사의 실제 구현부  
- read/write 반복  
- 오류 발생 시 즉시 중단  


### ✔ restore_backup_file()
- 공격 후 파일을 truncate(암호화 본문 제거)  
- 백업본을 다시 write하여 복구  


---
## 3. Blue2 파일시스템의 경로 설정(main) – mountpoint & backend 구조

Blue2는 FUSE 기반의 “Passthrough Filesystem” 구조를 사용하기 때문에  
**mountpoint(사용자가 접근하는 가상 디렉터리)**와  
**backend(실제 파일이 저장되는 실제 디렉터리)**를 명확히 분리해야 한다.

이 프로젝트에서는 다음과 같은 실행 구조를 갖는다:

```
./blue2 <mountpoint> <backend_path>
```

이를 위해 `blue2.c`의 main() 마지막 부분에서 사용자가 전달한  
mountpoint 및 backend 경로를 다음과 같이 처리했다:

```c
if (argc < 3) {
    fprintf(stderr, "Usage: %s <mountpoint> <backend>\n", argv[0]);
    return -1;
}

// mountpoint 설정
char *mountpoint = realpath(argv[1], NULL);
if (!mountpoint) {
    perror("realpath mountpoint");
    return -1;
}

// backend 설정
char backend_path[PATH_MAX];
if (!realpath(argv[2], backend_path)) {
    perror("realpath backend_path");
    return -1;
}

log_message("INFO: Protecting backend path: %s\n", backend_path);

// backend 디렉터리 FD 오픈
base_fd = open(backend_path, O_RDONLY | O_DIRECTORY);
if (base_fd == -1) {
    perror("Error opening backend directory");
    return -1;
}
```

### ✔ 설계 의도

- **mountpoint는 FUSE가 오버레이되는 가상 디렉터리**  
- **backend는 실제 파일이 저장되는 위치**  
- Blue2는 모든 파일 연산을 mountpoint에서 가로채고  
  backend에서 실제 파일을 읽고 쓰는 구조

### ✔ 왜 mountpoint = backend가 불가능한가?

FUSE는 mountpoint 위에 “가상 계층”을 덮어씌우므로  
mountpoint와 backend를 동일하게 설정하면  
실제 파일 접근이 불가능해지고 mount 자체가 실패한다.

따라서 이 프로젝트에서는:

- `mountpoint = ~/workspace/target` (공격 및 보호 대상)
- `backend = ~/workspace/real_target` (실제 저장소)

이 구조를 강제하도록 설계했다.

### ✔ Restore 및 스코어링 시스템과의 연동

- 모든 write/unlink/rename/create 이벤트는 mountpoint에서 발생한다.
- Blue2는 이를 감지해 Analyzer → Process Tracker → Restore 모듈이 동작한다.
- 실제 파일 조작은 backend에서 이루어지므로  
  복구/백업이 안전하게 진행될 수 있다.

요약하자면:

```
mountpoint = 공격이 들어오는 경로(감시 대상)
backend     = 원본 파일을 안전히 보관하는 실제 경로
```

이 두 경로를 분리 설정하는 구조가  
이 프로젝트 전체 동작의 근간이 된다.


# 3. 주목할 만한 포인트 요약

- **병렬 암호화/멀티프로세싱(Ransomware)에 특화된 PPID 그룹 스코어링**
- **Copy-on-Write 기반 백업으로 비용·용량 최적화**
- **공격 이벤트(WRITE/CREATE/UNLINK/RENAME)에만 복구 수행 → 불필요한 오버헤드 제거**
- **openat/fstatat 기반 안전한 파일 경로 접근**
- **restore(복구)기능을 통해 엔트로피 계산, 화이트리스트 등의 방어 기능을 넘어 파일이 공격되더라도 원본을 백업해 잃지 않도록 함**
- **restore 영역을 700권한으로 격리하여 랜섬웨어가 백업본 접근 불가**
- **PID 점수 + PPID 점수의 이중 방어 구조**


