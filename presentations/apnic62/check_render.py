#!/usr/bin/env python3
"""Render check for apnic62 Marp presentation: HTML slide count + PDF page count."""
import re
import subprocess
import sys
from pathlib import Path


def check_html(path: Path, expected: int) -> bool:
    text = path.read_text(encoding="utf-8")
    count = len(re.findall(r'data-marpit-svg="', text))
    ok = count == expected
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] HTML slides: {count} (expected {expected})")
    return ok


def check_pdf(path: Path, expected: int) -> bool:
    try:
        out = subprocess.check_output(["pdfinfo", str(path)], stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"  [FAIL] PDF: could not run pdfinfo ({e})")
        return False
    m = re.search(r"^Pages:\s+(\d+)", out, re.MULTILINE)
    if not m:
        print("  [FAIL] PDF: could not parse page count from pdfinfo")
        return False
    count = int(m.group(1))
    ok = count == expected
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] PDF pages:  {count} (expected {expected})")
    return ok


def check_size(path: Path, min_kb: int) -> bool:
    kb = path.stat().st_size // 1024
    ok = kb >= min_kb
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {path.name}: {kb} KB (min {min_kb} KB)")
    return ok


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <html> <pdf> <expected-slides>")
        return 2

    html_path = Path(sys.argv[1])
    pdf_path = Path(sys.argv[2])
    expected = int(sys.argv[3])

    results = []

    print(f"\nRender check — {expected} slides expected\n")

    print(f"HTML: {html_path}")
    if not html_path.exists():
        print("  [FAIL] file not found")
        results.append(False)
    else:
        results.append(check_size(html_path, min_kb=100))
        results.append(check_html(html_path, expected))

    print(f"\nPDF:  {pdf_path}")
    if not pdf_path.exists():
        print("  [FAIL] file not found")
        results.append(False)
    else:
        results.append(check_size(pdf_path, min_kb=200))
        results.append(check_pdf(pdf_path, expected))

    passed = sum(results)
    total = len(results)
    print(f"\n{'OK' if all(results) else 'FAIL'} — {passed}/{total} checks passed\n")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
