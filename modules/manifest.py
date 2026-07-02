"""
PhantomHash — Manifest Engine
═══════════════════════════════════════════════════════════════
A "manifest" is a trusted snapshot of a set of files' SHA-256
hashes, sizes, and timestamps.  Comparing the current state of
files against a manifest tells you EXACTLY which files were:
  • ADDED    — present now, not in manifest
  • DELETED  — in manifest, not present now
  • MODIFIED — present in both, but SHA-256 differs
  • OK       — present in both, SHA-256 matches

Two output formats:
  • JSON   (rich metadata, machine-readable — default)
  • SHA256 (simple text format: "<hash>  <path>" per line,
            compatible with `sha256sum --check` on Linux/macOS)
"""

import os
import json
import time
from datetime import datetime
from modules.hasher import hash_file, _human_size


def create_manifest(paths: list, label: str = "", base_dir: str = "") -> dict:
    """
    Hash every file in `paths` and return a manifest dict.
    `base_dir`: if set, store relative paths instead of absolute ones
    (makes manifests portable across machines).
    """
    entries = {}
    errors = []

    for path in paths:
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            errors.append({"path": path, "error": "Not a file or not found"})
            continue
        result = hash_file(path, algorithms=["sha256", "md5", "sha512"])
        if "error" in result:
            errors.append({"path": path, "error": result["error"]})
            continue

        key = os.path.relpath(path, base_dir) if base_dir else path
        entries[key] = {
            "sha256":      result["hashes"]["sha256"],
            "md5":         result["hashes"]["md5"],
            "sha512":      result["hashes"]["sha512"],
            "size_bytes":  result["size_bytes"],
            "size_human":  result["size_human"],
            "mtime":       result["mtime"],
            "filetype":    result["filetype"],
            "entropy":     result["entropy"],
        }

    return {
        "label":      label,
        "created_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "base_dir":   base_dir,
        "file_count": len(entries),
        "entries":    entries,
        "errors":     errors,
    }


def scan_directory(directory: str, recursive: bool = True,
                   extensions: list = None, label: str = "") -> dict:
    """
    Walk a directory tree and build a manifest of every file found.
    `extensions`: if given, only include files with these extensions (e.g. [".py",".js"])
    """
    directory = os.path.abspath(directory)
    if not os.path.isdir(directory):
        return {"error": f"Not a directory: {directory}"}

    paths = []
    if recursive:
        for root, _, files in os.walk(directory):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                if extensions:
                    if not any(fname.lower().endswith(e) for e in extensions):
                        continue
                paths.append(fpath)
    else:
        for fname in sorted(os.listdir(directory)):
            fpath = os.path.join(directory, fname)
            if os.path.isfile(fpath):
                if extensions and not any(fname.lower().endswith(e) for e in extensions):
                    continue
                paths.append(fpath)

    manifest = create_manifest(paths, label=label, base_dir=directory)
    manifest["scanned_directory"] = directory
    manifest["recursive"] = recursive
    return manifest


def save_manifest_json(manifest: dict, output_path: str):
    with open(output_path, "w") as f:
        json.dump(manifest, f, indent=2)


def save_manifest_sha256(manifest: dict, output_path: str):
    """
    Writes a `sha256sum`-compatible text file:
        <sha256>  <filepath>
    One line per file. Verifiable with: sha256sum --check <file>
    """
    with open(output_path, "w") as f:
        f.write(f"# PhantomHash manifest — {manifest.get('label','')}\n")
        f.write(f"# Created: {manifest.get('created_at','')}\n")
        f.write(f"# Files: {manifest.get('file_count', 0)}\n")
        for path, info in manifest["entries"].items():
            f.write(f"{info['sha256']}  {path}\n")


def load_manifest(path: str) -> dict:
    """Load a JSON manifest from disk."""
    with open(path) as f:
        return json.load(f)


def verify_manifest(manifest: dict, base_dir: str = "") -> dict:
    """
    Re-hash every file referenced in the manifest and compare against
    the stored SHA-256. Returns a detailed report per file.
    """
    results = {
        "ok": [],
        "modified": [],
        "missing": [],
        "added": [],
        "summary": {},
    }

    base = base_dir or manifest.get("base_dir", "")

    for rel_path, expected in manifest["entries"].items():
        abs_path = os.path.join(base, rel_path) if base else rel_path

        if not os.path.exists(abs_path):
            results["missing"].append({
                "path": rel_path,
                "expected_sha256": expected["sha256"],
            })
            continue

        result = hash_file(abs_path, algorithms=["sha256"])
        if "error" in result:
            results["missing"].append({"path": rel_path, "error": result["error"]})
            continue

        current_sha256 = result["hashes"]["sha256"]
        if current_sha256 == expected["sha256"]:
            results["ok"].append({"path": rel_path, "sha256": current_sha256})
        else:
            results["modified"].append({
                "path": rel_path,
                "expected_sha256": expected["sha256"],
                "actual_sha256":   current_sha256,
                "expected_size":   expected["size_bytes"],
                "actual_size":     result["size_bytes"],
                "expected_mtime":  expected["mtime"],
                "actual_mtime":    result["mtime"],
            })

    results["summary"] = {
        "total_checked": len(manifest["entries"]),
        "ok":       len(results["ok"]),
        "modified": len(results["modified"]),
        "missing":  len(results["missing"]),
        "verdict":  "CLEAN" if not results["modified"] and not results["missing"] else "TAMPERED",
    }
    return results


def diff_manifests(manifest_a: dict, manifest_b: dict) -> dict:
    """
    Compare two manifests (e.g. before and after a software update) and
    identify every file that was added, removed, or changed between them.
    """
    keys_a = set(manifest_a["entries"])
    keys_b = set(manifest_b["entries"])

    added   = []
    removed = []
    changed = []
    unchanged = []

    for k in sorted(keys_b - keys_a):
        added.append({"path": k, **manifest_b["entries"][k]})

    for k in sorted(keys_a - keys_b):
        removed.append({"path": k, **manifest_a["entries"][k]})

    for k in sorted(keys_a & keys_b):
        ea = manifest_a["entries"][k]
        eb = manifest_b["entries"][k]
        if ea["sha256"] != eb["sha256"]:
            changed.append({
                "path": k,
                "sha256_before": ea["sha256"],
                "sha256_after":  eb["sha256"],
                "size_before":   ea["size_bytes"],
                "size_after":    eb["size_bytes"],
            })
        else:
            unchanged.append(k)

    return {
        "manifest_a_label": manifest_a.get("label", "A"),
        "manifest_b_label": manifest_b.get("label", "B"),
        "added":     added,
        "removed":   removed,
        "changed":   changed,
        "unchanged": unchanged,
        "summary": {
            "added":     len(added),
            "removed":   len(removed),
            "changed":   len(changed),
            "unchanged": len(unchanged),
        },
    }
