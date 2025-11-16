# Ransomware Battle - 시스템 보안 프로젝트

단국대학교 시스템보안 과목의 팀 프로젝트 레포지토리입니다. FUSE 기반 실시간 랜섬웨어 방어 시스템과 다양한 공격 모듈을 포함합니다.

> ⚠️ **법적·윤리적 고지**: 이 코드는 교육·연구 목적으로만 사용해야 하며, 반드시 격리된 안전한 환경에서만 다뤄야 합니다.

## 프로젝트 구조

```
ransonware-battle/
├── defense/              # 방어 시스템 (FUSE 기반)
│   └── base64_dynamic_whitelist/
│       └── src/          # 방어 모듈 소스 코드
├── attack/               # 공격 모듈 (랜섬웨어 시뮬레이션)
│   ├── basic_attack_module/      # AES-256-CBC 암호화 공격
│   └── base64_attack_module/     # Base64 인코딩 공격
└── README.md
```

## 공격 모듈 (Attack Modules)

### 1. basic_attack_module
- **암호화 방식**: AES-256-CBC (OpenSSL)
- **특징**: 높은 엔트로피 데이터 생성, 표준 암호화 공격 시뮬레이션
- **확장자**: `.enc`

### 2. base64_attack_module
- **인코딩 방식**: Base64 (표준 C 라이브러리)
- **특징**: 
  - 저엔트로피 우회 시도 (엔트로피 기반 감지 우회)
  - 파일 크기 4/3배 증가
  - OpenSSL 의존성 없음
- **확장자**: `.enc`

**자세한 내용**: [attack/README.md](attack/README.md)

## 방어 시스템 (Defense System)

FUSE 기반 실시간 랜섬웨어 방어 시스템으로, PID 기반 행동 추적 및 다양한 탐지 기법을 사용합니다.

### 주요 방어 기법

#### 1. **Malice Score 기반 차단**
- PID별 행동 점수 추적
- 임계값(80점) 초과 시 프로세스 강제 종료
- **점수 체계**:
  - WRITE 작업: +1점 (엔트로피 4.2 이상 시 +5점 추가)
  - UNLINK/RENAME: +3점

#### 2. **엔트로피 분석**
- Shannon 엔트로피 계산 (0.0 ~ 8.0)
- 높은 엔트로피(≥4.2) 데이터 감지
- 암호화된 데이터 탐지

#### 3. **랜섬웨어 확장자 감지**
- 알려진 랜섬웨어 확장자 30개 이상 검사
- `.encrypted`, `.locked`, `.crypto` 등
- 감지 시 즉시 프로세스 강제 종료

#### 4. **파일 크기 변화 분석**
- Base64 인코딩 감지 (4/3배 비율)
- 원본 대비 크기 변화 비율 모니터링
- 의심 패턴 감지 시 PID 출력

#### 5. **구간별 엔트로피 패턴 감지**
- 파일을 1MB 청크 단위로 분석
- 높은/낮은 엔트로피 구간 반복 패턴 감지
- 부분 암호화 공격 탐지 (4번 이상 반복 시 차단)

#### 6. **더미 파일(낚시 파일) 시스템**
- 자동 생성된 더미 파일 접근 시 즉시 차단
- 랜섬웨어 탐지 및 차단

#### 7. **동적 화이트리스트**
- 초기화 시점 백엔드 디렉터리 자동 스캔
- 화이트리스트 파일: 모든 작업 허용
- 비화이트리스트 파일: 실행만 차단

#### 8. **로깅 시스템**
- 모든 보안 이벤트 기록
- 기본 로그 파일: `./ransomware_defense.log`
- 타임스탬프 및 상세 정보 포함

### 방어 모듈 구조

```
defense/base64_dynamic_whitelist/src/
├── blue2.c              # FUSE 파일시스템 메인
├── analyzer.c           # 점수 계산 모듈
├── entropy.c            # 엔트로피 계산
├── extension_checker.c  # 확장자 검사
├── file_size_tracker.c  # 파일 크기 추적
├── pattern_detector.c   # 구간별 패턴 감지
├── logger.c             # 로깅 시스템
├── whitelist.c          # 화이트리스트 관리
├── dummy_file.c         # 더미 파일 관리
└── process_tracker.c    # PID 추적
```

**자세한 내용**: [defense/base64_dynamic_whitelist/src/README.md](defense/base64_dynamic_whitelist/src/README.md)

## 빌드 및 실행

### 방어 시스템 빌드
```bash
cd defense/base64_dynamic_whitelist
make
./blue2 <mountpoint>
```

### 공격 모듈 빌드
```bash
# AES-256-CBC 공격 모듈
cd attack/basic_attack_module
make
./ransomware -e <target_directory>

# Base64 공격 모듈
cd attack/base64_attack_module
make
./ransomware -e <target_directory>
```

## 주요 특징

- **모듈화 설계**: 각 기능이 독립적인 모듈로 분리
- **실시간 탐지**: FUSE를 통한 파일시스템 레벨 모니터링
- **다층 방어**: 여러 탐지 기법을 통한 포괄적 방어
- **연구 목적**: 교육 및 연구를 위한 시뮬레이션 환경
