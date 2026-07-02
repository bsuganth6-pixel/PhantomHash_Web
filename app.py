#!/usr/bin/env python3
"""
PhantomHash — File Integrity & Hash Analysis Platform
═══════════════════════════════════════════════════════════════
Tabs:
  Hash File      — upload a file, get MD5/SHA1/SHA256/SHA512/BLAKE2b/CRC32
  Hash Text      — paste text, get all hashes instantly
  Compare Files  — upload two files, see if they match
  Verify Hash    — paste a known hash, confirm a file matches it
  Manifest       — generate a JSON or SHA256 manifest for uploaded files
"""

import os
import json
import tempfile
import secrets

from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename

from modules import hasher, manifest as manifest_mod

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024   # 500 MB

UPLOAD_DIR = tempfile.mkdtemp(prefix="phantomhash_")


def _save_upload(f):
    fname = secure_filename(f.filename) or "upload"
    path = os.path.join(UPLOAD_DIR, secrets.token_hex(8) + "_" + fname)
    f.save(path)
    return path


def _cleanup(*paths):
    for p in paths:
        try:
            if p and os.path.exists(p):
                os.remove(p)
        except OSError:
            pass


# ════════════════════════════════════════════════════════════════
#  PAGE ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html", active="hash")

@app.route("/compare")
def compare_page():
    return render_template("compare.html", active="compare")

@app.route("/verify")
def verify_page():
    return render_template("verify.html", active="verify")

@app.route("/manifest")
def manifest_page():
    return render_template("manifest.html", active="manifest")


# ════════════════════════════════════════════════════════════════
#  API
# ════════════════════════════════════════════════════════════════

@app.route("/api/hash/file", methods=["POST"])
def api_hash_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename."}), 400

    algorithms = request.form.getlist("algorithms") or None
    path = _save_upload(f)
    try:
        result = hasher.hash_file(path, algorithms=algorithms)
    finally:
        _cleanup(path)
    return jsonify(result)


@app.route("/api/hash/text", methods=["POST"])
def api_hash_text():
    data = request.get_json(force=True)
    text = data.get("text", "")
    if not text:
        return jsonify({"error": "No text provided."}), 400
    result = hasher.hash_text(text)
    return jsonify(result)


@app.route("/api/compare", methods=["POST"])
def api_compare():
    if "file_a" not in request.files or "file_b" not in request.files:
        return jsonify({"error": "Two files required (file_a and file_b)."}), 400

    path_a = _save_upload(request.files["file_a"])
    path_b = _save_upload(request.files["file_b"])
    try:
        result = hasher.compare_files(path_a, path_b)
    finally:
        _cleanup(path_a, path_b)
    return jsonify(result)


@app.route("/api/verify", methods=["POST"])
def api_verify():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    known_hash = (request.form.get("known_hash") or "").strip().lower()
    if not known_hash:
        return jsonify({"error": "No known hash provided."}), 400

    path = _save_upload(request.files["file"])
    try:
        # Auto-detect algorithm from hash length
        algo = _detect_algo(known_hash)
        if not algo:
            return jsonify({"error": "Unrecognised hash length. Supported: MD5 (32), SHA-1 (40), SHA-256 (64), SHA-512 (128), BLAKE2b (128)."}), 400
        result = hasher.hash_file(path, algorithms=[algo])
    finally:
        _cleanup(path)

    if "error" in result:
        return jsonify(result), 500

    computed = result["hashes"].get(algo, "")
    match = computed == known_hash
    return jsonify({
        "match": match,
        "verdict": "✓ MATCH — file is intact" if match else "✗ MISMATCH — file is different or corrupted",
        "algorithm": algo.upper(),
        "known_hash": known_hash,
        "computed_hash": computed,
        "filename": result["filename"],
        "size_human": result["size_human"],
    })


@app.route("/api/manifest/create", methods=["POST"])
def api_manifest_create():
    if "files" not in request.files:
        return jsonify({"error": "No files uploaded."}), 400

    label = request.form.get("label", "PhantomHash Manifest")
    fmt   = request.form.get("format", "json").lower()

    files = request.files.getlist("files")
    saved_paths = []
    name_map = {}

    for f in files:
        if f.filename:
            path = _save_upload(f)
            saved_paths.append(path)
            name_map[path] = f.filename

    if not saved_paths:
        return jsonify({"error": "No valid files uploaded."}), 400

    # Use original filenames for manifest keys
    entries = {}
    errors = []
    for path in saved_paths:
        r = hasher.hash_file(path, algorithms=["sha256", "md5", "sha512"])
        orig_name = name_map.get(path, os.path.basename(path))
        if "error" in r:
            errors.append({"path": orig_name, "error": r["error"]})
        else:
            entries[orig_name] = {
                "sha256":     r["hashes"]["sha256"],
                "md5":        r["hashes"]["md5"],
                "sha512":     r["hashes"]["sha512"],
                "size_bytes": r["size_bytes"],
                "size_human": r["size_human"],
                "mtime":      r["mtime"],
                "filetype":   r["filetype"],
                "entropy":    r["entropy"],
            }

    from datetime import datetime
    mf = {
        "label": label,
        "created_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "file_count": len(entries),
        "entries": entries,
        "errors": errors,
    }

    _cleanup(*saved_paths)

    if fmt == "sha256":
        lines = [f"# PhantomHash Manifest — {label}\n",
                 f"# Created: {mf['created_at']}\n"]
        for fname, info in entries.items():
            lines.append(f"{info['sha256']}  {fname}\n")
        return jsonify({"format": "sha256", "content": "".join(lines), "manifest": mf})

    return jsonify({"format": "json", "content": json.dumps(mf, indent=2), "manifest": mf})


@app.route("/api/manifest/verify", methods=["POST"])
def api_manifest_verify():
    """Upload a JSON manifest + the actual files, verify all of them."""
    if "manifest" not in request.files:
        return jsonify({"error": "No manifest file uploaded."}), 400

    manifest_path = _save_upload(request.files["manifest"])
    try:
        with open(manifest_path) as fp:
            mf = json.load(fp)
    except Exception as e:
        _cleanup(manifest_path)
        return jsonify({"error": f"Invalid manifest JSON: {e}"}), 400

    files = request.files.getlist("files")
    saved = {}
    for f in files:
        if f.filename:
            path = _save_upload(f)
            orig = secure_filename(f.filename)
            saved[orig] = path

    results = {"ok": [], "modified": [], "missing": [], "not_in_manifest": []}

    for name, expected in mf.get("entries", {}).items():
        base = os.path.basename(name)
        if base not in saved:
            results["missing"].append({"path": name, "expected_sha256": expected["sha256"]})
            continue
        r = hasher.hash_file(saved[base], algorithms=["sha256"])
        computed = r["hashes"]["sha256"]
        if computed == expected["sha256"]:
            results["ok"].append({"path": name, "sha256": computed})
        else:
            results["modified"].append({
                "path": name,
                "expected_sha256": expected["sha256"],
                "actual_sha256": computed,
            })

    for name in saved:
        if name not in {os.path.basename(k) for k in mf.get("entries", {})}:
            results["not_in_manifest"].append(name)

    _cleanup(manifest_path, *saved.values())

    verdict = "CLEAN" if not results["modified"] and not results["missing"] else "TAMPERED"
    results["summary"] = {
        "total_checked": len(mf.get("entries", {})),
        "ok": len(results["ok"]),
        "modified": len(results["modified"]),
        "missing": len(results["missing"]),
        "not_in_manifest": len(results["not_in_manifest"]),
        "verdict": verdict,
    }
    return jsonify(results)


def _detect_algo(h: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(len(h), "")


if __name__ == "__main__":
    print(r"""
   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
        H A S H  —  File Integrity & Hash Analysis Platform
        Running at http://127.0.0.1:5051
    """)
    app.run(debug=True, host="127.0.0.1", port=5051)
