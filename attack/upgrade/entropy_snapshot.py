#!/usr/bin/env python3
import os
import sys
import math
import csv
import argparse
from collections import Counter
from typing import Tuple, Iterator, List


def compute_entropy(file_path: str) -> Tuple[int, float]:
    """
    파일의 크기(바이트)와 셰넌 엔트로피(비트/바이트)를 계산합니다.
    비어있는 파일은 엔트로피 0.0을 반환합니다.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception:
        # 접근 불가/깨진 링크 등은 크기 -1, 엔트로피 -1.0으로 표기
        return -1, -1.0

    size_bytes = len(data)
    if size_bytes == 0:
        return 0, 0.0

    counts = Counter(data)
    n = float(size_bytes)
    entropy = 0.0
    for cnt in counts.values():
        p = cnt / n
        entropy -= p * math.log(p, 2)
    return size_bytes, round(entropy, 6)


def iter_files(root_dir: str) -> Iterator[str]:
    """
    루트 디렉터리부터 재귀적으로 모든 일반 파일 경로를 순회합니다.
    심볼릭 링크는 따라가지 않습니다.
    """
    for dirpath, _, filenames in os.walk(root_dir, followlinks=False):
        for name in filenames:
            yield os.path.join(dirpath, name)


def write_csv(rows: Iterator[Tuple[str, int, float]], output_csv: str) -> None:
    """
    (Path, SizeBytes, Entropy) 행들을 CSV로 저장합니다.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_csv)), exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Path", "SizeBytes", "Entropy"])
        for path, size_bytes, entropy in rows:
            writer.writerow([path, size_bytes, entropy])


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="디렉터리 내부 모든 파일의 셰넌 엔트로피를 계산해 CSV로 저장합니다."
    )
    p.add_argument(
        "directory",
        help="대상 루트 디렉터리 경로",
    )
    p.add_argument(
        "-o",
        "--output",
        default="entropy_snapshot.csv",
        help="출력 CSV 경로 (기본값: entropy_snapshot.csv)",
    )
    return p


def main(argv: List[str]) -> int:
    parser = build_argparser()
    args = parser.parse_args(argv)

    target_dir = os.path.abspath(args.directory)
    if not os.path.isdir(target_dir):
        print(f"Error: Not a directory: {args.directory}", file=sys.stderr)
        return 2

    def generate_rows() -> Iterator[Tuple[str, int, float]]:
        for path in iter_files(target_dir):
            size_bytes, entropy = compute_entropy(path)
            # 항상 입력 디렉터리 기준 상대경로로 기록
            display_path = os.path.relpath(path, start=target_dir)
            yield (display_path, size_bytes, entropy)

    write_csv(generate_rows(), args.output)
    print(f"Wrote CSV: {os.path.abspath(args.output)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


