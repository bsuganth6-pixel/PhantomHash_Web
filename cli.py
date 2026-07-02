#!/usr/bin/env python3
"""
PhantomHash CLI — File Integrity & Hash Analysis
═══════════════════════════════════════════════════════════════
USAGE
  python3 cli.py hash   <file> [file2 ...]     Hash one or more files
  python3 cli.py text   <string>               Hash a string / text value
  python3 cli.py compare <file_a> <file_b>     Compare two files
  python3 cli.py verify  <file> --hash <hash>  Verify file against a known hash
  python3 cli.py manifest create <file> [...]  Generate an integrity manifest
  python3 cli.py manifest verify <manifest.json> <file> [...]
  python3 cli.py --help
"""

import os
import sys
import json
import argparse
import textwrap
import time

from modules import hasher, manifest as manifest_mod

# ── ANSI colours ─────────────────────────────────────────────
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
def _c(code): return code if _COLOR else ""
R  = _c("\033[0m");  BOLD = _c("\033[1m");  DIM = _c("\033[2m")
RED = _c("\033[91m"); GRN = _c("\033[92m"); YLW = _c("\033[93m")
CYN = _c("\033[96m"); VIO = _c("\033[95m")


def banner():

    print(f"""{CYN}{BOLD}
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
              ██╗  ██╗ █████╗ ███████╗██╗  ██╗
              ██║  ██║██╔══██╗██╔════╝██║  ██║
              ███████║███████║███████╗███████║
              ██╔══██║██╔══██║╚════██║██╔══██║
              ██║  ██║██║  ██║███████║██║  ██║
              ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
  {DIM}File Integrity & Hash Analysis Platform{R}
""")


def err(msg):  print(f"{RED}✗ {msg}{R}", file=sys.stderr)
def ok(msg):   print(f"{GRN}✓ {msg}{R}")
def info(msg): print(f"{CYN}ℹ {msg}{R}")
def warn(msg): print(f"{YLW}⚠ {msg}{R}")

SEP = f"{DIM}{'─' * 78}{R}"


# ════════════════════════════════════════════════════════════════
#  DISPLAY HELPERS
# ════════════════════════════════════════════════════════════════

ALGO_NOTES = {
    "md5":     "MD5     (32) — fast, non-cryptographic",
    "sha1":    "SHA-1   (40) — deprecated",
    "sha256":  "SHA-256 (64) — current standard ★",
    "sha512":  "SHA-512(128) — high margin",
    "blake2b": "BLAKE2b(128) — fastest modern",
    "crc32":   "CRC32    (8) — error detection only",
}

def print_hash_result(r, show_entropy=True):
    print()
    print(f"  {BOLD}File:{R}     {r['filename']}")
    print(f"  {DIM}Size:{R}     {r['size_human']}  ({r['size_bytes']} bytes)")
    print(f"  {DIM}Type:{R}     {r['filetype']}")
    print(f"  {DIM}Modified:{R} {r['mtime']}")
    print(f"  {DIM}Hashed in:{R} {r['elapsed_seconds']}s")
    print()
    print(SEP)
    print(f"  {'ALGORITHM':<14} {'HASH VALUE'}")
    print(SEP)
    for algo, val in r["hashes"].items():
        label = ALGO_NOTES.get(algo, algo.upper())
        note = label.split("—")[1].strip() if "—" in label else ""
        prefix = algo.upper()
        if algo == "sha256":
            print(f"  {CYN}{BOLD}{prefix:<14}{R} {CYN}{val}{R}  {DIM}← recommended{R}")
        else:
            print(f"  {DIM}{prefix:<14}{R} {val}  {DIM}({note}){R}")
    print(SEP)

    if show_entropy and "entropy" in r:
        e = r["entropy"]
        if e >= 7.5:   ecol = RED;  elabel = "VERY HIGH — likely encrypted or compressed"
        elif e >= 6.5: ecol = YLW;  elabel = "HIGH — possibly packed or encoded"
        else:          ecol = GRN;  elabel = "NORMAL"
        bar_len = int((e / 8.0) * 30)
        bar = "█" * bar_len + "░" * (30 - bar_len)
        print(f"  Entropy: {ecol}{e:.4f}{R}  {ecol}{bar}{R}  {DIM}{elabel}{R}")
    print()


def print_verify_result(r):
    match = r["match"]
    col  = GRN if match else RED
    icon = "✓" if match else "✗"
    print()
    print(f"  {col}{BOLD}{icon}  {r['verdict']}{R}")
    print()
    print(f"  {'Algorithm:':<16} {r['algorithm']}")
    print(f"  {'File:':<16} {r['filename']} ({r['size_human']})")
    print(SEP)
    print(f"  {'Known hash:':<16} {DIM}{r['known_hash']}{R}")
    print(f"  {'Computed:':<16} {col}{r['computed_hash']}{R}")
    print(SEP)
    if not match:
        warn("The file may be corrupted, tampered, or you may have the wrong file.")
    print()


def print_compare_result(r):
    col  = GRN if r["identical"] else RED
    icon = "✓" if r["identical"] else "✗"
    a, b = r["file_a"], r["file_b"]
    print()
    print(f"  {col}{BOLD}{icon}  Files are {r['verdict']}{R}")
    print()
    print(f"  {'File A:':<14} {a['filename']}  ({a['size_human']})")
    print(f"  {'File B:':<14} {b['filename']}  ({b['size_human']})")
    print(SEP)
    print(f"  {'SHA-256 A:':<14} {CYN if r['identical'] else RED}{a['hashes']['sha256']}{R}")
    print(f"  {'SHA-256 B:':<14} {CYN if r['identical'] else RED}{b['hashes']['sha256']}{R}")
    if "md5" in a["hashes"]:
        md5_match = a["hashes"]["md5"] == b["hashes"]["md5"]
        col2 = GRN if md5_match else RED
        print(f"  {'MD5 A:':<14} {col2}{a['hashes']['md5']}{R}")
        print(f"  {'MD5 B:':<14} {col2}{b['hashes']['md5']}{R}")
    print(SEP)
    print()


def print_manifest_summary(mf):
    print()
    print(f"  {BOLD}Manifest:{R}  {mf.get('label','—')}")
    print(f"  {DIM}Created:{R}   {mf.get('created_at','—')}")
    print(f"  {DIM}Files:{R}     {mf.get('file_count', 0)}")
    print()
    print(SEP)
    print(f"  {'FILENAME':<40} {'SHA-256 (first 24 chars)…'}")
    print(SEP)
    for path, info in mf["entries"].items():
        short = os.path.basename(path)
        print(f"  {CYN}{short:<40}{R} {DIM}{info['sha256'][:24]}…{R}  {info['size_human']}")
    if mf.get("errors"):
        for e in mf["errors"]:
            print(f"  {RED}ERR  {e['path']}: {e['error']}{R}")
    print(SEP)
    print()


def print_verify_manifest_result(r):
    s = r["summary"]
    col = GRN if s["verdict"] == "CLEAN" else RED
    print()
    print(f"  {col}{BOLD}VERDICT: {s['verdict']}{R}")
    print()
    print(f"  {GRN}OK:       {s['ok']}{R}")
    print(f"  {RED}Modified: {s['modified']}{R}")
    print(f"  {RED}Missing:  {s['missing']}{R}")
    print(f"  {DIM}Total:    {s['total_checked']}{R}")
    print()
    print(SEP)

    if r["ok"]:
        print(f"  {GRN}{'PASS':<8}{R} {'FILE'}")
        for e in r["ok"]:
            print(f"  {GRN}✓ OK{R}    {os.path.basename(e['path'])}")

    if r["modified"]:
        print()
        print(f"  {RED}{'FAIL':<8}{R} {'FILE'}")
        for e in r["modified"]:
            print(f"  {RED}✗ MOD{R}   {os.path.basename(e['path'])}")
            print(f"  {DIM}  Expected: {e['expected_sha256'][:32]}…{R}")
            print(f"  {RED}  Got:      {e['actual_sha256'][:32]}…{R}")

    if r["missing"]:
        print()
        for e in r["missing"]:
            print(f"  {RED}✗ MISS{R}  {os.path.basename(e['path'])}")

    print(SEP)
    print()


# ════════════════════════════════════════════════════════════════
#  COMMANDS
# ════════════════════════════════════════════════════════════════

def cmd_hash(args):
    algos = args.algorithms.split(",") if args.algorithms else None
    for path in args.files:
        r = hasher.hash_file(path, algorithms=algos)
        if "error" in r:
            err(r["error"]); continue

        if args.json:
            print(json.dumps(r, indent=2))
        else:
            print_hash_result(r, show_entropy=not args.no_entropy)

        if args.output:
            with open(args.output, "w") as f:
                json.dump(r, f, indent=2)
            ok(f"Saved to {args.output}")


def cmd_text(args):
    text = " ".join(args.text) if isinstance(args.text, list) else args.text
    r = hasher.hash_text(text)

    if args.json:
        print(json.dumps(r, indent=2))
        return

    print()
    print(f"  {BOLD}Input:{R} {DIM}{r['input_text']}{R}")
    print(f"  {DIM}Bytes:{R} {r['byte_length']}  Entropy: {r['entropy']}")
    print()
    print(SEP)
    for algo, val in r["hashes"].items():
        label = algo.upper()
        print(f"  {label:<10} {CYN}{val}{R}")
    print(SEP)
    print()


def cmd_compare(args):
    r = hasher.compare_files(args.file_a, args.file_b)
    if "error" in r:
        err(r["error"]); sys.exit(1)

    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print_compare_result(r)
    sys.exit(0 if r["identical"] else 1)


def cmd_verify(args):
    r = hasher.hash_file(args.file)
    if "error" in r:
        err(r["error"]); sys.exit(2)

    known = args.hash.strip().lower()
    algo_map = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
    algo = args.algorithm or algo_map.get(len(known))

    if not algo:
        err(f"Cannot detect algorithm from hash length ({len(known)} chars). "
            f"Use --algorithm md5|sha1|sha256|sha512.")
        sys.exit(2)

    if algo not in r["hashes"]:
        r2 = hasher.hash_file(args.file, algorithms=[algo])
        r["hashes"][algo] = r2["hashes"].get(algo, "")

    computed = r["hashes"].get(algo, "")
    match = computed == known

    result = {
        "match":         match,
        "verdict":       "✓ MATCH — file is intact" if match else "✗ MISMATCH — file differs",
        "algorithm":     algo.upper(),
        "filename":      r["filename"],
        "size_human":    r["size_human"],
        "known_hash":    known,
        "computed_hash": computed,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_verify_result(result)
    sys.exit(0 if match else 1)


def cmd_manifest_create(args):
    paths = args.files
    label = args.label or f"PhantomHash Manifest — {time.strftime('%Y-%m-%d %H:%M')}"

    if not args.json:
        info(f"Hashing {len(paths)} file(s)…")
    mf = manifest_mod.create_manifest(paths, label=label)

    if not args.json:
        print_manifest_summary(mf)

    if args.output:
        out = args.output
        if args.format == "sha256":
            manifest_mod.save_manifest_sha256(mf, out)
        else:
            manifest_mod.save_manifest_json(mf, out)
        if not args.json:
            ok(f"Manifest saved → {out}")
    elif args.json:
        print(json.dumps(mf, indent=2))
    else:
        # Print sha256sum format to stdout if no output path given
        print(f"# {label}")
        for path, info_ in mf["entries"].items():
            print(f"{info_['sha256']}  {path}")


def cmd_manifest_verify(args):
    try:
        mf = manifest_mod.load_manifest(args.manifest)
    except Exception as e:
        err(f"Cannot load manifest: {e}"); sys.exit(2)

    if not args.json:
        info(f"Verifying {len(mf['entries'])} file(s) from manifest '{mf.get('label','?')}'…")

    base = args.base_dir or os.path.dirname(os.path.abspath(args.manifest))
    r = manifest_mod.verify_manifest(mf, base_dir=base)

    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print_verify_manifest_result(r)
    sys.exit(0 if r["summary"]["verdict"] == "CLEAN" else 1)


# ════════════════════════════════════════════════════════════════
#  ARGPARSE
# ════════════════════════════════════════════════════════════════

def build_parser():
    p = argparse.ArgumentParser(
        prog="cli.py",
        description="PhantomHash — File Integrity & Hash Analysis CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="command", required=True)

    # ── hash ──
    sp = sub.add_parser("hash", help="Hash one or more files")
    sp.add_argument("files", nargs="+")
    sp.add_argument("-a", "--algorithms", default=None,
                    help="Comma-separated algorithms: md5,sha1,sha256,sha512,blake2b,crc32 (default: all)")
    sp.add_argument("--no-entropy", action="store_true", help="Skip entropy display")
    sp.add_argument("--json",   action="store_true", help="Also print raw JSON output")
    sp.add_argument("-o", "--output", default=None, help="Save JSON result to file")
    sp.set_defaults(func=cmd_hash)

    # ── text ──
    sp = sub.add_parser("text", help="Hash a string / text value")
    sp.add_argument("text", nargs="+", help="Text to hash (quote multi-word strings)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_text)

    # ── compare ──
    sp = sub.add_parser("compare", help="Compare two files (exits 0=identical, 1=different)")
    sp.add_argument("file_a")
    sp.add_argument("file_b")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_compare)

    # ── verify ──
    sp = sub.add_parser("verify", help="Verify file against a known hash (exits 0=match, 1=mismatch)")
    sp.add_argument("file")
    sp.add_argument("--hash", required=True, help="Known hash value (MD5/SHA-1/SHA-256/SHA-512 — auto-detected)")
    sp.add_argument("--algorithm", default=None, help="Force algorithm (md5|sha1|sha256|sha512)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_verify)

    # ── manifest ──
    msp = sub.add_parser("manifest", help="Create or verify integrity manifests")
    msub = msp.add_subparsers(dest="manifest_command", required=True)

    sc = msub.add_parser("create", help="Generate a manifest from files")
    sc.add_argument("files", nargs="+")
    sc.add_argument("-l", "--label",  default=None)
    sc.add_argument("-o", "--output", default=None, help="Save to this path (.json or .sha256sums)")
    sc.add_argument("-f", "--format", choices=["json","sha256"], default="json")
    sc.add_argument("--json", action="store_true")
    sc.set_defaults(func=cmd_manifest_create)

    sv = msub.add_parser("verify", help="Verify files against a manifest")
    sv.add_argument("manifest", help="Path to the JSON manifest file")
    sv.add_argument("files", nargs="*",
                    help="Files to check (if omitted, paths in manifest are used as-is)")
    sv.add_argument("--base-dir", default=None,
                    help="Base directory for resolving relative paths in the manifest")
    sv.add_argument("--json", action="store_true")
    sv.set_defaults(func=cmd_manifest_verify)

    return p


def main():
    if len(sys.argv) == 1:
        banner()
        build_parser().print_help()
        return
    args = build_parser().parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print(); info("Cancelled.")
        sys.exit(130)


if __name__ == "__main__":
    main()
