import os, time, tempfile, random, string
import os, time, random, string, re, unicodedata

# Re-implement needed functions to avoid heavy dependencies

def strip_trailing_overlay(file_path: str) -> bool:
    """Neutralizes polyglots and steganographic overlay exploits by truncating
    bytes past the legitimate end-of-file structural boundary (%%EOF in PDF,
    End of Central Directory record in ZIP/OOXML)."""
    try:
        ext = os.path.splitext(file_path)[1].lower()
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return False
        original_len = len(data)
        truncated_len = original_len
        if ext == ".pdf":
            eof_pos = data.rfind(b"%%EOF")
            if eof_pos != -1:
                end_pos = eof_pos + 5
                while end_pos < original_len and data[end_pos:end_pos+1] in (b"\r", b"\n", b" ", b"\t"):
                    end_pos += 1
                truncated_len = end_pos
        elif ext in (".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods"):
            eocd_pos = data.rfind(b"PK\x05\x06")
            if eocd_pos != -1 and eocd_pos + 22 <= original_len:
                comment_len = int.from_bytes(data[eocd_pos+20:eocd_pos+22], "little")
                expected_end = eocd_pos + 22 + comment_len
                if expected_end <= original_len:
                    truncated_len = expected_end
        if truncated_len < original_len:
            with open(file_path, "wb") as f:
                f.write(data[:truncated_len])
            return True
        return False
    except Exception:
        return False

def sanitize_unicode_text(text: str) -> str:
    """Sanitizes plain text or XML node values to prevent invisible character abuse, homoglyph spoofing, and bidirectional layout injection (Trojan Source)."""
    if not text:
        return ""
    pattern = r"[\u200B-\u200F\uFEFF\u00AD\u202A-\u202E\u2066-\u2069]"
    cleaned = re.sub(pattern, "", text)
    return unicodedata.normalize("NFKC", cleaned)


def generate_random_file(ext, size_kb):
    fd, path = tempfile.mkstemp(suffix=ext)
    with os.fdopen(fd, 'wb') as f:
        f.write(os.urandom(size_kb * 1024))
    return path

def benchmark_strip_overlay(ext, size_kb, iterations=5):
    path = generate_random_file(ext, size_kb)
    # Append EOF marker for PDF or EOCD for ZIP to simulate valid file
    if ext == '.pdf':
        with open(path, 'ab') as f:
            f.write(b'%%EOF\n')
    elif ext in ('.zip', '.docx', '.xlsx', '.pptx'):
        # simple EOCD structure (PK\x05\x06) with comment length 0
        with open(path, 'ab') as f:
            f.write(b'PK\x05\x06' + (0).to_bytes(2, 'little') + (0).to_bytes(2, 'little'))
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        strip_trailing_overlay(path)
        elapsed = time.perf_counter() - start
        times.append(elapsed)
    os.remove(path)
    return sum(times)/len(times)

def benchmark_unicode(text_len, iterations=5):
    text = ''.join(random.choice(string.ascii_letters + '\u200B\u202E') for _ in range(text_len))
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        sanitize_unicode_text(text)
        times.append(time.perf_counter() - start)
    return sum(times)/len(times)

if __name__ == '__main__':
    print('Benchmark: strip_trailing_overlay')
    for size in [10, 100, 1024]:  # KB
        for ext in ['.pdf', '.zip']:
            avg = benchmark_strip_overlay(ext, size)
            print(f'  {ext} {size}KB avg: {avg*1000:.2f} ms')
    print('\nBenchmark: sanitize_unicode_text')
    for length in [1000, 10000, 50000]:
        avg = benchmark_unicode(length)
        print(f'  text length {length} avg: {avg*1000:.2f} ms')
