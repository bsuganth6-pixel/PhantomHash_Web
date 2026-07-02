"""
PhantomHash — Core Hashing Engine
═══════════════════════════════════════════════════════════════
Supports: MD5, SHA-1, SHA-256, SHA-512, BLAKE2b, CRC32
All hashes are computed in a SINGLE streaming pass over the file,
so even a 4 GB file is processed without loading it into memory.

Why multiple algorithms?
  • MD5    — Fast, widely used for non-security checksums. DO NOT use
             for security-critical integrity checks; collisions exist.
  • SHA-1  — Deprecated for security, still appears in legacy manifests/git.
  • SHA-256 — Current recommended standard for integrity verification.
  • SHA-512 — Stronger than SHA-256, useful when extra margin is desired.
  • BLAKE2b — Faster than SHA-256 on modern CPUs, equally secure.
             Used by modern tools (e.g. IPFS, Argon2 internally).
  • CRC32  — Not cryptographic at all; used only for quick transmission
             error detection (zip files, network frames). Trivially forkable.
"""

import os
import math
import struct
import hashlib
import zlib
import time
from datetime import datetime

CHUNK_SIZE = 1024 * 1024   # 1 MB read chunks — large enough for throughput, fits in RAM fine

# ── Magic-byte → filetype map ─────────────────────────────────
MAGIC_SIGNATURES = [
    (b"MZ",           "Windows PE Executable / DLL"),
    (b"\x7fELF",      "Linux/UNIX ELF Executable"),
    (b"PK\x03\x04",   "ZIP / JAR / DOCX / XLSX / APK Archive"),
    (b"PK\x05\x06",   "ZIP (empty archive)"),
    (b"%PDF",         "PDF Document"),
    (b"\xd0\xcf\x11\xe0", "MS Office Legacy (OLE2 — .doc/.xls/.ppt)"),
    (b"\x1f\x8b",    "GZIP Archive"),
    (b"BZh",         "BZIP2 Archive"),
    (b"\xfd7zXZ\x00","XZ Archive"),
    (b"Rar!",        "RAR Archive"),
    (b"7z\xbc\xaf'", "7-Zip Archive"),
    (b"\x89PNG\r\n", "PNG Image"),
    (b"\xff\xd8\xff", "JPEG Image"),
    (b"GIF87a",      "GIF87 Image"),
    (b"GIF89a",      "GIF89 Image"),
    (b"RIFF",        "RIFF Container (WAV / AVI)"),
    (b"ftyp",        "MP4 / MOV Video"),             # at offset 4
    (b"ID3",         "MP3 Audio (ID3 tag)"),
    (b"\x1aE\xdf\xa3","MKV / WebM Video"),
    (b"#!",          "Shell Script / Shebang"),
    (b"<?xml",       "XML Document"),
    (b"{\n",         "JSON (likely)"),
    (b"<!DOCTYPE",   "HTML Document"),
    (b"<html",       "HTML Document"),
]


def detect_filetype(data: bytes) -> str:
    for sig, name in MAGIC_SIGNATURES:
        if data[:len(sig)] == sig:
            return name
        # ftyp box is at offset 4 in MP4
        if sig == b"ftyp" and data[4:8] == sig:
            return name
    return "Unknown / Binary"


def shannon_entropy(data: bytes) -> float:
    """
    Shannon entropy in bits per byte (0.0 = all identical bytes, 8.0 = perfectly random).
    High entropy (> 7.2) usually means the file is compressed, encrypted, or packed.
    """
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def hash_file(path: str, algorithms: list = None) -> dict:
    """
    Hash a file with all requested algorithms in a single streaming pass.
    Returns a rich dict of results including metadata, entropy, and filetype.

    algorithms: list of strings from {"md5","sha1","sha256","sha512","blake2b","crc32"}
                defaults to all six.
    """
    if algorithms is None:
        algorithms = ["md5", "sha1", "sha256", "sha512", "blake2b", "crc32"]

    algorithms = [a.lower() for a in algorithms]

    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}
    if not os.path.isfile(path):
        return {"error": f"Not a file: {path}"}

    size = os.path.getsize(path)
    stat = os.stat(path)

    # Initialise hashers
    hashers = {}
    if "md5"     in algorithms: hashers["md5"]     = hashlib.md5()
    if "sha1"    in algorithms: hashers["sha1"]    = hashlib.sha1()
    if "sha256"  in algorithms: hashers["sha256"]  = hashlib.sha256()
    if "sha512"  in algorithms: hashers["sha512"]  = hashlib.sha512()
    if "blake2b" in algorithms: hashers["blake2b"] = hashlib.blake2b()
    crc = 0

    # Sample the first 8 KB for filetype + entropy estimate (avoids loading whole file)
    header_sample = b""
    entropy_sample = b""  # up to 256 KB for entropy
    start_time = time.time()

    try:
        with open(path, "rb") as f:
            first_chunk = True
            bytes_read = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                for h in hashers.values():
                    h.update(chunk)
                if "crc32" in algorithms:
                    crc = zlib.crc32(chunk, crc) & 0xFFFFFFFF
                if first_chunk:
                    header_sample = chunk[:8192]
                    first_chunk = False
                if bytes_read < 256 * 1024:
                    entropy_sample += chunk[:max(0, 256 * 1024 - bytes_read)]
                bytes_read += len(chunk)
    except PermissionError:
        return {"error": f"Permission denied: {path}"}
    except OSError as e:
        return {"error": str(e)}

    elapsed = time.time() - start_time

    # Collect digests
    hashes = {}
    for name, h in hashers.items():
        hashes[name] = h.hexdigest()
    if "crc32" in algorithms:
        hashes["crc32"] = f"{crc:08x}"

    entropy = shannon_entropy(entropy_sample)
    filetype = detect_filetype(header_sample)

    # Entropy interpretation
    if entropy >= 7.5:
        entropy_label = "VERY HIGH — likely encrypted or compressed"
        entropy_severity = "high"
    elif entropy >= 6.5:
        entropy_label = "HIGH — possibly packed or encoded"
        entropy_severity = "medium"
    elif entropy >= 4.0:
        entropy_label = "NORMAL — typical for text/binary"
        entropy_severity = "none"
    else:
        entropy_label = "LOW — mostly uniform content (sparse file or text)"
        entropy_severity = "none"

    return {
        "path": path,
        "filename": os.path.basename(path),
        "size_bytes": size,
        "size_human": _human_size(size),
        "filetype": filetype,
        "hashes": hashes,
        "entropy": round(entropy, 4),
        "entropy_label": entropy_label,
        "entropy_severity": entropy_severity,
        "elapsed_seconds": round(elapsed, 3),
        "mtime": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
    }


def compare_files(path_a: str, path_b: str) -> dict:
    """
    Hash both files with SHA-256 and return whether they are identical,
    plus a rich side-by-side summary.
    """
    a = hash_file(path_a, ["sha256", "md5"])
    b = hash_file(path_b, ["sha256", "md5"])

    if "error" in a:
        return {"error": a["error"]}
    if "error" in b:
        return {"error": b["error"]}

    identical = a["hashes"]["sha256"] == b["hashes"]["sha256"]
    return {
        "identical": identical,
        "verdict": "IDENTICAL" if identical else "DIFFERENT",
        "file_a": a,
        "file_b": b,
    }


def hash_text(text: str, algorithms: list = None) -> dict:
    """Hash a raw string (for quick paste-and-check use cases)."""
    if algorithms is None:
        algorithms = ["md5", "sha1", "sha256", "sha512"]

    data = text.encode("utf-8")
    hashes = {}
    for algo in algorithms:
        try:
            h = hashlib.new(algo)
            h.update(data)
            hashes[algo] = h.hexdigest()
        except ValueError:
            pass

    return {
        "input_text": text[:200] + ("…" if len(text) > 200 else ""),
        "byte_length": len(data),
        "hashes": hashes,
        "entropy": round(shannon_entropy(data), 4),
    }


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"
