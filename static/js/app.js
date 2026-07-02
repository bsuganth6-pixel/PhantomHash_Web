// PhantomHash — Shared frontend utilities

const PH = {
  esc(str) {
    if (str == null) return "";
    return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  },

  async postJSON(url, body) {
    const r = await fetch(url, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body||{}) });
    return r.json();
  },

  async postForm(url, formData) {
    const r = await fetch(url, { method:"POST", body:formData });
    return r.json();
  },

  setLoading(loader, btn, on) {
    if (loader) loader.classList.toggle("active", on);
    if (btn) btn.disabled = on;
  },

  // ── Toast ──
  toast(msg, type="info", ms=3500) {
    const c = document.getElementById("toast-container"); if(!c) return;
    const el = document.createElement("div"); el.className=`toast ${type}`;
    const icon = type==="success"?"circle-check":type==="error"?"circle-exclamation":"circle-info";
    el.innerHTML=`<i class="fa-solid fa-${icon}"></i><span>${this.esc(msg)}</span>`;
    c.appendChild(el);
    setTimeout(()=>{ el.style.animation="toastOut 0.2s ease forwards"; setTimeout(()=>el.remove(),200); }, ms);
  },

  // ── Clipboard ──
  async copy(text, label="Hash") {
    try { await navigator.clipboard.writeText(text); this.toast(`${label} copied!`, "success"); }
    catch { this.toast("Clipboard access denied.", "error"); }
  },

  // ── File chip label ──
  fileChip(name, size) {
    const kb = size ? ` · ${(size/1024).toFixed(1)} KB` : "";
    return `<span class="file-chip"><i class="fa-solid fa-file"></i>${this.esc(name)}${kb}</span>`;
  },

  // ── Drop zone setup ──
  initDropZone(zoneId, inputId, labelId, multiple=false) {
    const zone  = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    const label = document.getElementById(labelId);
    if (!zone || !input) return;

    const updateLabel = () => {
      const files = [...input.files];
      label.innerHTML = files.length
        ? files.map(f => this.fileChip(f.name, f.size)).join("")
        : `<div class="drop-icon"><i class="fa-solid fa-upload"></i></div>
           <div class="drop-label"><strong>Drop file${multiple?"s":""} here</strong> or click to browse</div>`;
    };

    input.multiple = multiple;
    input.addEventListener("change", updateLabel);
    zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("drag-over"); });
    zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
    zone.addEventListener("drop", e => {
      e.preventDefault(); zone.classList.remove("drag-over");
      const dt = e.dataTransfer;
      if (dt.files.length) {
        const container = new DataTransfer();
        [...dt.files].forEach(f => container.items.add(f));
        input.files = container.files;
        updateLabel();
      }
    });
  },

  // ── Entropy bar render ──
  renderEntropy(entropy) {
    const pct = Math.min(100, (entropy / 8) * 100);
    let color = "#00FF88";
    if (entropy >= 7.5) color = "#FF3B5C";
    else if (entropy >= 6.5) color = "#FFD23F";
    else if (entropy >= 4.0) color = "#00F5FF";

    const labels = {
      high:   "VERY HIGH — likely encrypted or compressed",
      medium: "HIGH — possibly packed or encoded",
      none:   entropy < 4 ? "LOW — mostly uniform content" : "NORMAL — typical binary/text",
    };
    const severity = entropy >= 7.5 ? "high" : entropy >= 6.5 ? "medium" : "none";
    const labelText = labels[severity];

    return `
      <div class="entropy-row">
        <div class="entropy-bar-wrap">
          <div class="entropy-label-text">Entropy: <strong>${labelText}</strong></div>
          <div class="entropy-bar-bg">
            <div class="entropy-bar-fill" style="width:${pct}%;background:${color}"></div>
          </div>
        </div>
        <div class="entropy-value" style="color:${color}">${entropy}</div>
      </div>`;
  },

  // ── Hash table row ──
  hashRow(algo, value, note) {
    const display = {
      md5:    {name:"MD5",     note:"32-char — fast, non-cryptographic"},
      sha1:   {name:"SHA-1",   note:"40-char — deprecated for security"},
      sha256: {name:"SHA-256", note:"64-char — current standard"},
      sha512: {name:"SHA-512", note:"128-char — extra margin"},
      blake2b:{name:"BLAKE2b", note:"128-char — fastest modern option"},
      crc32:  {name:"CRC32",   note:"8-char — error detection only"},
    };
    const d = display[algo] || {name:algo.toUpperCase(), note:""};
    return `
      <tr>
        <td><div class="algo-name">${d.name}</div><div class="algo-note">${d.note}</div></td>
        <td><div class="hash-value">${this.esc(value)}</div></td>
        <td><button class="btn btn-secondary btn-sm hash-copy-btn" onclick="PH.copy('${this.esc(value)}','${d.name}')">
          <i class="fa-solid fa-copy"></i> Copy
        </button></td>
      </tr>`;
  },

  // ── File meta pills ──
  renderMeta(r) {
    return `
      <div class="file-meta">
        <div class="meta-pill"><i class="fa-solid fa-file"></i><span>File</span><strong>${this.esc(r.filename)}</strong></div>
        <div class="meta-pill"><i class="fa-solid fa-weight-hanging"></i><span>Size</span><strong>${this.esc(r.size_human)}</strong></div>
        <div class="meta-pill"><i class="fa-solid fa-code"></i><span>Type</span><strong>${this.esc(r.filetype)}</strong></div>
        <div class="meta-pill"><i class="fa-solid fa-clock"></i><span>Modified</span><strong>${this.esc(r.mtime)}</strong></div>
        <div class="meta-pill"><i class="fa-solid fa-gauge"></i><span>Speed</span><strong>${r.elapsed_seconds}s</strong></div>
      </div>`;
  },
};
