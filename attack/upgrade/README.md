# auto_making_vimtic_file.py 

## 요구 사항
- Python 3.8+
- 표준 라이브러리만 사용(추가 패키지 불필요)


## 사용법
스크립트를 실행하면 기본적으로 현재 작업 디렉터리에 `dataset/` 폴더를 생성하고, 그 안에 테스트 파일들을 만듭니다.

- 기본 실행
```
python upgrade/auto_making_victim_file.py
```

- 생성 루트 디렉터리 지정(예: `my_dataset`)
```
python upgrade/auto_making_victim_file.py my_dataset
```


## 생성되는 구조(요약)
```
<BASE>/
  text_small/        # txt, csv 등(소형·초소형 텍스트 위주)
  text_large/        # json 등(중형 텍스트)
  docs_pdf/          # pdf-like(헤더만 흉내낸 더미)
  docs_office/       # (현재 샘플 없음, 확장 예정 포인트)
  images/            # png 더미(랜덤 바이트)
  media/             # mp4 더미(랜덤 바이트)
  archives/          # zip-like/gz/tar 등(엔트로피 높은 파일 포함)
  db/                # sqlite DB
  binaries_readonly/ # exe 더미(읽기 전용으로 설정)
  special/
    readonly/        # 읽기 전용 파일
    hidden/          # 숨김 파일명 패턴(.hidden_*)
    deep_path/       # 매우 깊은 경로(서브디렉터리 25단계)
    locked/          # (자리표시자) 잠금 관련 실험용 디렉터리
    links/           # (자리표시자) 링크 관련 실험용 디렉터리
```


## 생성 항목과 수량(기본값)
- 텍스트/CSV/JSON: 소~중형 위주
- PDF-like: 수 MB~수십 MB 더미
- ZIP-like(대용량): 0.5~1.5GB 더미 1개(용량 주의)
- SQLite DB: 수백~수천 행
- gzip/tar 아카이브: 소~중형
- 바이너리/이미지/미디어: 임의 크기 더미
- 특수 케이스: 읽기 전용/숨김/깊은 경로

수량은 스크립트 루프(예: `for i in range(…)`)를 조정하여 쉽게 줄이거나 늘릴 수 있습니다.


## 안전 가이드
- 반드시 테스트 전용 디렉터리(예: 가상머신 내 `~/sandbox/dataset`)를 사용하세요.
- 초대형 파일 생성(archives/big_*.zip-like)은 디스크 여유 공간을 충분히 확보한 후 활성화하세요.
- 읽기 전용 파일/깊은 경로는 일부 툴에서 삭제·정리가 번거로울 수 있습니다.


## 커스터마이즈 포인트
- 생성 규모 축소/확대: 각 `for` 루프의 반복 횟수/사이즈 상한 조정
- 파일 타입 추가: 유사한 패턴으로 새로운 `gen_*` 함수를 추가


## 참고
- `pdf-like`, `zip-like` 파일은 “식별 헤더를 흉내 낸 더미”로, 실제 포맷 호환성을 보장하지 않습니다.
- 방어 실험에서 “엔트로피 높은 파일”과 “평문 텍스트”를 함께 사용해 탐지 기준(행위/엔트로피/확장자 등)을 폭넓게 평가하세요.


# entropy_snapshot.py — 디렉터리 엔트로피 스냅샷

디렉터리(하위 포함)의 모든 파일에 대해 셰넌 엔트로피(비트/바이트)를 계산해 CSV로 저장합니다. 사전/사후 CSV를 만들어 `.enc` 제거 매칭으로 엔트로피 변화를 비교할 때 사용하세요.

## 요구 사항
- Python 3.8+
- 추가 패키지 불필요(표준 라이브러리)

## 사용법
- 기본 실행(상대경로 기록, 기본 출력 파일: `entropy_snapshot.csv`)
```
python3 upgrade/entropy_snapshot.py /path/to/dir
```
- 출력 파일 지정
```
python3 upgrade/entropy_snapshot.py /path/to/dir -o before.csv
```

## 출력(CSV)
- 컬럼: `Path, SizeBytes, Entropy`
  - Path: 입력한 루트 디렉터리 기준 상대경로
  - SizeBytes: 파일 크기(바이트). 읽기 실패 시 -1
  - Entropy: 셰넌 엔트로피(비트/바이트). 읽기 실패 시 -1.0

## 워크플로우 예시
1) 사전 스냅샷
```
python3 upgrade/entropy_snapshot.py /data -o before.csv
```
2) 암호화 실행(별도 모듈)
3) 사후 스냅샷
```
python3 upgrade/entropy_snapshot.py /data -o after.csv
```
4) 비교(개요)
- after.csv의 `Path`에서 `.enc` 확장자를 제거한 값을 키로 하여, before.csv의 `Path`와 매칭 → `Entropy(After) - Entropy(Before)` 비교

## 해석 가이드
- 텍스트/CSV/JSON: 대개 3~5 → 7.8~8.0 근접으로 상승
- zip/png/mp4 등 고엔트로피 파일: 변화가 작음


---

# join_entropy_csv.py — before/after CSV 조인

`entropy_snapshot.py`로 만든 사전(before)·사후(after) CSV를 조인해, `.enc` 확장자 제거 매칭 기반으로 엔트로피 변화를 계산해 줍니다.

## 사용법
- 사전 스냅샷 생성
```
python3 upgrade/entropy_snapshot.py /path/to/dir -o before.csv
```
- 사후 스냅샷 생성
```
python3 upgrade/entropy_snapshot.py /path/to/dir -o after.csv
```
- 조인/비교 실행
```
python3 upgrade/join_entropy_csv.py before.csv after.csv -o entropy_diff.csv
```
- 읽기 실패(-1) 항목 제외 옵션
```
python3 upgrade/join_entropy_csv.py before.csv after.csv -o entropy_diff.csv --skip-errors
```

## 출력(CSV)
- 컬럼: `PathBase, EntropyBefore, EntropyAfter, Delta, SizeBefore, SizeAfter`
  - PathBase: 매칭 기준 경로(사후의 `.enc` 제거 결과와 사전 Path가 일치)
  - Delta: `EntropyAfter - EntropyBefore`

## 주의
- before/after 모두 같은 루트 디렉터리에 대해 스냅샷을 만들어야 상대경로 키가 일치합니다.
- 원본 삭제 정책 등으로 인해 매칭되지 않는 항목은 결과에서 제외될 수 있습니다.

## end-to-end 
### 1) 테스트 데이터 생성
python .\upgrade\auto_making_victim_file.py ".\dataset"

### 2) 사전 스냅샷
python .\upgrade\entropy_snapshot.py ".\dataset" -o ".\before.csv"

## (여기서 사용자/툴이 파일들을 암호화하고 *.enc 확장자를 추가했다고 가정)
### 3) 사후 스냅샷
python .\upgrade\entropy_snapshot.py ".\dataset" -o ".\after.csv"

### 4) 조인 및 변화량 계산
python .\upgrade\join_entropy_csv.py ".\before.csv" ".\after.csv" -o ".\entropy_diff.csv"