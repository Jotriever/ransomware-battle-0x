#!/usr/bin/env python3
import csv
import sys
import os
import argparse
from typing import Dict, Any, List


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="before.csv와 after.csv를 조인해 엔트로피 변화를 계산합니다 (.enc 매칭)."
    )
    p.add_argument("before_csv", help="사전 스냅샷 CSV (entropy_snapshot.py 출력)")
    p.add_argument("after_csv", help="사후 스냅샷 CSV (entropy_snapshot.py 출력)")
    p.add_argument(
        "-o",
        "--output",
        default="entropy_diff.csv",
        help="출력 CSV (기본값: entropy_diff.csv)",
    )
    p.add_argument(
        "--skip-errors",
        action="store_true",
        help="SizeBytes/Entropy가 -1(읽기 실패)인 항목은 조인·출력을 건너뜁니다.",
    )
    return p


def load_keyed(path: str, strip_enc: bool) -> Dict[str, Dict[str, Any]]:
    keyed: Dict[str, Dict[str, Any]] = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {"Path", "SizeBytes", "Entropy"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(f"CSV 컬럼에 {required} 가 포함되어야 합니다: {path}")
        for row in reader:
            p = row["Path"]
            key = p[:-4] if (strip_enc and p.lower().endswith(".enc")) else p
            keyed[key] = row
    return keyed


def parse_float(v: str) -> float:
    try:
        return float(v)
    except Exception:
        return -1.0


def parse_int(v: str) -> int:
    try:
        return int(v)
    except Exception:
        return -1


def main(argv: List[str]) -> int:
    args = build_argparser().parse_args(argv)

    before = load_keyed(args.before_csv, strip_enc=False)
    after = load_keyed(args.after_csv, strip_enc=True)

    out_rows: List[Dict[str, Any]] = []
    for key, b in before.items():
        a = after.get(key)
        if not a:
            continue

        eb = parse_float(b["Entropy"])
        ea = parse_float(a["Entropy"])
        sb = parse_int(b["SizeBytes"])
        sa = parse_int(a["SizeBytes"])

        if args.skip_errors:  # type: ignore[attr-defined]
            if eb < 0 or ea < 0 or sb < 0 or sa < 0:
                continue

        out_rows.append(
            {
                "PathBase": key,
                "EntropyBefore": eb,
                "EntropyAfter": ea,
                "Delta": round(ea - eb, 6) if (eb >= 0 and ea >= 0) else "",
                "SizeBefore": sb,
                "SizeAfter": sa,
            }
        )

    os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        fn = [
            "PathBase",
            "EntropyBefore",
            "EntropyAfter",
            "Delta",
            "SizeBefore",
            "SizeAfter",
        ]
        w = csv.DictWriter(f, fieldnames=fn)
        w.writeheader()
        w.writerows(out_rows)

    print(f"Wrote: {os.path.abspath(args.output)} rows: {len(out_rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


