# #️⃣ PhantomHash

**File Integrity & Hash Analysis Platform.** Multi-algorithm hashing,
tamper detection, manifest generation/verification, file comparison,
and hash verification — with a web UI and a full CLI.

Day 2 of the Phantom Security toolkit.

---

## Features

| Feature | Web UI | CLI |
|---|---|---|
| Hash file (MD5 / SHA-1 / SHA-256 / SHA-512 / BLAKE2b / CRC32) | ✅ | ✅ |
| Hash text / string | ✅ | ✅ |
| Compare two files (bit-for-bit) | ✅ | ✅ |
| Verify file against a known hash | ✅ | ✅ |
| Generate integrity manifest (JSON or sha256sum format) | ✅ | ✅ |
| Verify files against a manifest (tamper detection) | ✅ | ✅ |
| Shannon entropy analysis (packed/encrypted detection) | ✅ | ✅ |
| Magic-byte filetype detection | ✅ | ✅ |
| Streaming — handles files of any size without loading into RAM | ✅ | ✅ |
| `--json` flag (clean parseable output for scripting/piping) | — | ✅ |
| Meaningful exit codes (0=ok, 1=mismatch/tampered, 2=error) | — | ✅ |

---

## Setup

```bash
pip install -r requirements.txt

# Web UI (http://127.0.0.1:5051)
python3 app.py

# CLI
python3 cli.py --help
```

---

## CLI Usage

```bash
# Hash a file (all algorithms)
python3 cli.py hash file.zip

# Hash with specific algorithms only
python3 cli.py hash file.zip -a sha256,md5

# Hash a text string
python3 cli.py text "hello world"

# Compare two files
python3 cli.py compare original.iso downloaded.iso
# exits 0 = identical, 1 = different

# Verify a file against a known hash (auto-detects algorithm from length)
python3 cli.py verify ubuntu.iso --hash 3b8d5...

# Generate a manifest (saved as JSON)
python3 cli.py manifest create *.py -o manifest.json --label "v1.0 release"

# Verify files against that manifest later
python3 cli.py manifest verify manifest.json
# exits 0 = CLEAN, 1 = TAMPERED/MISSING

# Get clean JSON output for scripting
python3 cli.py hash file.bin --json | jq '.hashes.sha256'
python3 cli.py verify file.bin --hash abc123... --json | jq '.match'
```

---

## Web UI Tabs

- **Hash File / Text** — Upload a file or paste text, choose algorithms, see results with entropy bar
- **Compare Files** — Drop two files side-by-side, see green=match / red=mismatch per hash
- **Verify Hash** — Paste a known hash, upload the file, get an immediate pass/fail
- **Manifest** — Generate a manifest → download it → verify later to detect any changes

---

## Deploying to Vercel

PhantomHash is **stateless** — every request hashes the uploaded file, returns results, and discards the file. It's a perfect fit for Vercel serverless.

```bash
# Just push with vercel.json already included
vercel --prod
```

The `vercel.json` is already configured:
```json
{ "rewrites": [{ "source": "/(.*)", "destination": "/app.py" }] }
```

**Note:** File uploads go to `/tmp` (auto-handled in Flask's `tempfile.mkdtemp`). This works fine on Vercel since we clean up after every request. Max file size is 500 MB (Vercel's 4.5 MB request limit applies on free tier — adjust for large files).

---

## Algorithms Explained

| Algorithm | Length | Use |
|---|---|---|
| MD5 | 32 hex | Fast checksums — **never use for security**, collisions exist |
| SHA-1 | 40 hex | Deprecated — SHAttered collision (2017) |
| SHA-256 | 64 hex | **Current standard** — recommended for all integrity checks |
| SHA-512 | 128 hex | Stronger margin than SHA-256 |
| BLAKE2b | 128 hex | Faster than SHA-256 on modern CPUs, equally secure |
| CRC32 | 8 hex | Error detection only — trivially forgeable |

---

## What Entropy Tells You

Shannon entropy measures randomness (0.0 = all identical bytes, 8.0 = perfectly random).

| Entropy Range | Meaning |
|---|---|
| < 4.0 | Mostly uniform — sparse file or plain text |
| 4.0 – 6.5 | Normal binary/executable content |
| 6.5 – 7.5 | Possibly compressed or encoded |
| > 7.5 | **Likely encrypted, packed, or obfuscated** |

High entropy alone doesn't mean malicious — but it's a useful signal when combined with a suspicious extension or filetype mismatch.

---

## Project Structure

```
phantomhash/
├── app.py                    ← Flask web UI
├── cli.py                    ← CLI (same modules as web UI)
├── requirements.txt
├── vercel.json               ← Vercel deploy config
├── modules/
│   ├── hasher.py             ← Core hashing engine (streaming, all algos, entropy, filetype)
│   └── manifest.py           ← Manifest create / verify / diff / save / load
├── templates/
│   ├── base.html
│   ├── index.html            ← Hash file + text
│   ├── compare.html          ← Compare two files
│   ├── verify.html           ← Verify against known hash
│   └── manifest.html         ← Generate + verify manifests
└── static/
    ├── css/style.css
    └── js/
        ├── app.js            ← Drop zones, toasts, entropy bar, hash table helpers
        └── matrix.js
```

---


