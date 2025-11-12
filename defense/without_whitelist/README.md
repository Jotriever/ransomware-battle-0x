<p>FUSE-Guard: 실시간 랜섬웨어 방어 시스템 README

 `blue2.c`, `analyzer.c`, `entropy.c` 3개의 C 파일을 기반으로 구축된 **FUSE 기반 실시간 랜섬웨어 방어 시스템**의 전체 아키텍처와 방어 전략을 설명하는 readme 문서입니닥.

## 1. 아키텍처 개요

본 시스템은 두 개의 핵심 모듈이 협력하여 작동함

* blue2.c 
    * **역할:** FUSE의 '틀'이자 메인 프로그램
    * **핵심 기능:**
        1.  `fuse_get_context()`로 **PID 획득**.
        2.  **PID 기반 "회계 장부"** (`g_score_table`)를 관리하며 `update_malice_score`로 점수 누적
        3.  `KILL_THRESHOLD` (**150점**)를 기준으로 `kill(pid, SIGKILL)` **명령 실행**.
        4.  `myfs_write`에서 `pread`를 실행해 '원본 데이터'(`old_buf`)를 전달

* analyzer.c
    * **역할:** **점수 계산기** 
    * **핵심 기능:** get_score()  함수가 모든 방어 로직 (엔트로피, 변화량, 크기, 행위)을 계산하여 점수를 반환. 모든 '가중치'(`WEIGHT_...`)가 여기에 정의되어 있음
    * **[핵심]** '엔트로피 변화량'(Delta) 값을 받기 위해, 함수 인자를 `(const char* new_buf, const char* old_buf_or_null)`로 나누어 받도록 수정됨.

* entropy.c 
    * **역할:** calculate_entropy() 함수를 제공
    * **핵심 기능:** math.h의 log를 사용한 엔트로피를 정확히 계산


<!-- ## 2. 🎯 Red Team 공격 코드 분석 (Threat Model)

Red Team 코드(`main.c`, `file_ops.c`, `crypto.c`)는 다음과 같은 암호화 패턴을 사용

1.  **정찰 (`file_ops.c`):** `traverse_directory`가 `opendir`, `readdir`, `stat`를 호출하여 모든 하위 폴더와 파일을 스캔
2.  **암호화 (`crypto.c`):**
    * `fopen(input_file, "rb")`: **원본 파일**을 읽음.
    * `fopen(output_file, "wb")`: **새로운 `.enc` 파일**을 생성
    * `fwrite(...)`: 암호화된 데이터를 **새 `.enc` 파일**에 씀.
3.  **원본 파괴 (`file_ops.c`):** 암호화 성공 시 `remove(path_buffer)`로 **원본 파일을 삭제** -->

---

## 2. 핵심 방어 전략 (`analyzer.c` 상세)

### 2-1.  즉시 차단 (가중치 150점)

`KILL_THRESHOLD` 150점에 즉시 도달하는 2가지 핵심 전략

#### (1) '고엔트로피 암호화' 공격 
* **로직:** `WEIGHT_DELTA_ENTROPY` (150점)
* **설명:** "엔트로피 변화량(Delta)"을 계산 -> 빈파일에 '쓰기' 행위 시 쉽게 악성코드로 판단하는 것을 막기 위해 구현
* 
* **Red Team 대응:**
    * Red Team은 새 파일을 생성 `blue2.c`의 `myfs_write`는 이 새 파일에 `write`를 시도
    * `old_buf` (기존 데이터) = '빈 파일' (엔트로피 **0.0**)
    * `new_buf` (새 데이터) = 암호화된 데이터 (엔트로피 **~7.9**)
    * `delta` = 7.9, `new_entropy` = 7.9 <br>
* **오탐 방지 (핵심):** `if (delta > 3.0 && new_entropy > 6.0)`
    * 이 조건은 Red Team의 공격(`7.9 > 3.0 && 7.9 > 6.0` -> **True**)은 즉시 차단
    * 동시에, echo "normal text (delta 3.9, new_entropy 3.9) 같은 정상 쓰기는 오탐하지 않고 안전하게 통과시킴

#### (2) '저엔트로피 우회' 공격 (DoS 등)
* **로직:** `WEIGHT_LARGE_WRITE` (150점)
* **설명:** "어중간한 엔트로피"나 "단일 문자"로 덮어쓰는 우회 공격을 방어
* **핵심 조건:** if (size > 10MB)
* **효과:** 엔트로피 값과 관계없이, 단일 쓰기 호출의 크기(size)가 10MB를 초과하면 즉시 악성으로 판단

### 3-1. 반복 공격 누적 차단 (가중치 2~10점)

고엔트로피 공격을 피하기 위해 점수가 낮은 행위를 여러 번 반복하는 공격을 누적 점수로 차단

* **WEIGHT_MALICIOUS (10점):**
    * **대상:** unlink (파일 삭제), rename (이름 변경)
    * **의미:** 고위험 행위. Red Team의 '원본 파괴'(`remove`) 시도를 탐지한다. `150 / 10 = 15`번 반복 시 차단 (실제로는 `write`에서 먼저 차단될듯?) <br>
* **WEIGHT_MALICIOUS_LOW (2점):**
    * **대상:** read, open, getattr, readdir, create, mkdir 등
    * **의미:** 저위험 '정찰(Reconnaissance)' 행위. Red Team의 `traverse_directory` 스캔 공격을 탐지 `150 / 2 = 75`번 반복 시 차단
  

---

### 실제 코드 내의 가중치 및 임계치
/* analyzer.c */ <br>
##### 1. 내용 기반 <br>
`#define WEIGHT_WRITE 1`          // **기본 쓰기 (반복 누적용) 시 1점** <br>

##### 2. 행위 기반 <br>
`#define WEIGHT_MALICIOUS 10`      // (고위험) **삭제/이름변경 (반복 누적용)시 10점** (150점 / 10회) <br>
`#define WEIGHT_MALICIOUS_LOW 2`   // (저위험) **읽기/스캔/생성 (반복 누적용)시 2점** (150점 / 75회) <br>

##### 3. 맥락 기반 (즉시 차단 <br>
`#define WEIGHT_LARGE_WRITE 150`   // (저엔트로피 DoS)<br>
`#define LARGE_WRITE_THRESHOLD (10* 1024 * 1024)` **10MB 이상 덮어쓰면 150점** <br>

##### 4. 변화량 기반 (즉시 차단) <br>
`#define WEIGHT_DELTA_ENTROPY 150` // (고엔트로피 암호화)**기존 엔트로피에서 새로운 엔트로피를 계산했을 때 변화량이 3.0인경우 && 새 데이터가 6.0 인경우 150점** <br>
`#define ENTROPY_DELTA_THRESHOLD 3.0`  // 변화량이 3.0 이상인 경우 <br>
`#define HIGH_ENTROPY_FLOOR 6.0`   // (오탐 방지용 기준선) // 새 데이터의 엔트로피가 6.0 이상인 경우 <br>

<!-- 레드팀이 엔트로피와 malice_score 관련해서 공격 할 수 있는 방법 (생각나는 대로 그때그때 적어놓기)
(1)레드팀이 파일을 덮어쓰는게 아니라 create로 새로 만든 후 원본을 지워버리면 ? - 파일이 생성되는 것까지는 막지 않지만 빈 파일(엔트로피 0.0) 에 암호화된 데이터 (엔트로피 높음, ~7.9) 을 넣으면 
델타 검사: if (delta 7.9 > 3.0 && new_entropy 7.9 > 6.0) 에서 막혀서 악성코드로 판정됨 -->
