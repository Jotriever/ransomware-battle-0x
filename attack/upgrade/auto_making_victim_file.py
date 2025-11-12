import os, random, string, sqlite3, gzip, tarfile, io, time, sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "dataset"
random.seed(42)

def ensure_dir(p):
    os.makedirs(p, exist_ok=True)

def rand_bytes(n):
    return os.urandom(n)

def rand_text(n):
    alphabet = string.ascii_letters + string.digits + " 가나다라마바사아자차카타파하,.!?-_()[]{} "
    return "".join(random.choice(alphabet) for _ in range(n))

def write_file(path, data: bytes):
    ensure_dir(os.path.dirname(path))
    with open(path, "wb") as f:
        f.write(data)

def gen_text(path, size_bytes):
    write_file(path, rand_text(size_bytes).encode("utf-8"))

def gen_csv(path, rows, cols):
    lines = []
    for _ in range(rows):
        row = [rand_text(random.randint(3, 12)) for _ in range(cols)]
        lines.append(",".join(row))
    write_file(path, ("\n".join(lines) + "\n").encode("utf-8"))

def gen_json(path, count):
    import json
    arr = [{"id": i, "msg": rand_text(40)} for i in range(count)]
    write_file(path, json.dumps(arr, ensure_ascii=False, indent=2).encode("utf-8"))

def gen_bin(path, size_bytes):
    write_file(path, rand_bytes(size_bytes))

def gen_pdf_like(path, size_bytes):
    # 진짜 PDF는 아님(식별 헤더만), 엔트로피 테스트용
    data = b"%PDF-1.7\n" + rand_bytes(max(0, size_bytes - 9))
    write_file(path, data)

def gen_zip_like(path, size_bytes):
    # 실제 zip 아님(식별 헤더만), 엔트로피 테스트용
    data = b"PK\x03\x04" + rand_bytes(max(0, size_bytes - 4))
    write_file(path, data)

def gen_sqlite(path, rows):
    ensure_dir(os.path.dirname(path))
    conn = sqlite3.connect(path)
    c = conn.cursor()
    c.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, msg TEXT)")
    c.executemany("INSERT INTO t(msg) VALUES (?)", [(rand_text(100),) for _ in range(rows)])
    conn.commit()
    conn.close()

def gen_gzip(path, payload_size):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(rand_bytes(payload_size))
    write_file(path, buf.getvalue())

def gen_tar(path, num_files, each_size):
    ensure_dir(os.path.dirname(path))
    with tarfile.open(path, "w") as tar:
        for i in range(num_files):
            data = rand_bytes(each_size)
            info = tarfile.TarInfo(name=f"f{i}.bin")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

def touch_readonly(path, size_bytes):
    gen_bin(path, size_bytes)
    # Windows에서는 read-only 속성 설정
    os.chmod(path, 0o444)

def deep_path(base, depth):
    p = base
    for i in range(depth):
        # 경로에 한글/공백/특수문자 포함
        p = os.path.join(p, f"dir_{i:02d}_한글 스페이스")
    ensure_dir(p)
    return p

def main():
    # 하나의 디렉터리(BASE)에 확장자별 샘플 1개씩 생성
    ensure_dir(BASE)

    # 텍스트/구조화 데이터
    gen_text(os.path.join(BASE, "sample_text.txt"), random.randint(1024, 4096))
    gen_csv(os.path.join(BASE, "sample_data.csv"), rows=random.randint(50, 200), cols=random.randint(4, 12))
    gen_json(os.path.join(BASE, "sample.json"), count=random.randint(50, 150))

    # 문서/아카이브/DB
    gen_pdf_like(os.path.join(BASE, "sample.pdf"), size_bytes=random.randint(2_000_000, 8_000_000))
    gen_zip_like(os.path.join(BASE, "sample.zip"), size_bytes=random.randint(2_000_000, 8_000_000))
    gen_sqlite(os.path.join(BASE, "sample.sqlite"), rows=random.randint(300, 1000))
    gen_gzip(os.path.join(BASE, "sample.bin.gz"), payload_size=random.randint(100_000, 1_000_000))
    gen_tar(os.path.join(BASE, "sample.tar"), num_files=random.randint(5, 15), each_size=random.randint(2_048, 50_000))

    # 바이너리/이미지/미디어(더미 바이트)
    gen_bin(os.path.join(BASE, "sample.exe"), size_bytes=random.randint(200_000, 2_000_000))
    gen_bin(os.path.join(BASE, "sample.png"), size_bytes=random.randint(100_000, 1_000_000))
    gen_bin(os.path.join(BASE, "sample.mp4"), size_bytes=random.randint(2_000_000, 10_000_000))

    # 특수 케이스: 읽기 전용/숨김 파일
    touch_readonly(os.path.join(BASE, "readonly_sample.bin"), size_bytes=random.randint(5_000, 100_000))
    gen_text(os.path.join(BASE, ".hidden_sample.txt"), random.randint(100, 2_000))

    print(f"Done. Dataset root: {BASE}")

if __name__ == "__main__":
    t0 = time.time()
    main()
    print(f"Elapsed: {time.time() - t0:.2f}s")