/* ==========================================================================
 * SpectraVeil Lab — Frontend Interactive Controller (Port 4165)
 * ========================================================================== */

(function () {
  'use strict';

  // --------------------------------------------------------------------------
  // HELPERS
  // --------------------------------------------------------------------------
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  let toastTimer = null;
  function showToast(msg) {
    const el = $('#toast');
    if (!el) return;
    el.textContent = msg;
    el.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add('hidden'), 3200);
  }

  async function apiPost(url, body) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (!res.ok || data.ok === false) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return data;
  }

  function base64ToUint8(b64) {
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }

  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const res = String(reader.result || '');
        const idx = res.indexOf(',');
        resolve(idx !== -1 ? res.slice(idx + 1) : res);
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  function downloadBytes(bytes, filename, mimeType) {
    const blob = new Blob([bytes], { type: mimeType || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  }

  function escapeHtml(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // --------------------------------------------------------------------------
  // STUDIO TAB NAVIGATION
  // --------------------------------------------------------------------------
  function switchTab(tabId) {
    $$('.tab-btn').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.tab === tabId);
    });
    $$('.studio-panel').forEach((panel) => {
      panel.classList.toggle('active', panel.id === tabId);
    });
  }

  $$('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // ==========================================================================
  // STUDIO 01: ZERO-WIDTH UNICODE & CANARY LEAK TRAP
  // ==========================================================================

  $$('.submode-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      $$('.submode-btn').forEach((b) => b.classList.toggle('active', b === btn));
      const isCanary = btn.dataset.zwmode === 'canary';
      $('#zw-single-pane').classList.toggle('hidden', isCanary);
      $('#zw-canary-pane').classList.toggle('hidden', !isCanary);
    });
  });

  async function runZeroWidthEncode() {
    try {
      const data = await apiPost('/api/zerowidth/encode', {
        coverText: $('#zw-cover').value,
        secretText: $('#zw-secret').value,
        password: $('#zw-pass-enc').value,
        mode: $('#zw-alphabet').value
      });

      $('#zw-output').value = data.stegoText;
      $('#zw-enc-stats').textContent =
        `Hiển thị: ${data.stats.visibleChars} chữ • Ẩn: +${data.stats.invisibleCodePoints} hạt (${data.stats.envelopeByteLength} bytes${data.stats.compressed ? ', đã nén' : ''}${data.stats.encrypted ? ', AES-256' : ''})`;
      $('#zw-enc-result').classList.remove('hidden');
      showToast('✨ Đã nhúng tin mật tàng hình vào câu chat!');
      return data.stegoText;
    } catch (err) {
      showToast('❌ ' + err.message);
      return null;
    }
  }

  async function runZeroWidthDecode() {
    try {
      const data = await apiPost('/api/zerowidth/decode', {
        stegoText: $('#zw-decode-input').value,
        password: $('#zw-pass-dec').value
      });

      $('#zw-stat-vis').textContent = `${data.stats.visibleChars} ký tự`;
      $('#zw-stat-inv').textContent = `${data.stats.invisibleCodePoints} hạt ẩn`;
      $('#zw-stat-mode').textContent = data.detectedMode
        ? (data.detectedMode === 'vs256' ? 'VS-256 (8-bit)' : 'ZW-4 (2-bit)')
        : 'Sạch / Không rõ';

      // Render Codepoint Microscope
      const microEl = $('#zw-microscope');
      if (!data.microscope || data.microscope.length === 0) {
        microEl.innerHTML = '<span class="dim-hint">Chuỗi trống.</span>';
      } else {
        microEl.innerHTML = data.microscope.map((item) => {
          if (item.kind === 'visible') {
            const disp = item.char === ' ' ? '␣' : escapeHtml(item.char);
            return `<span class="cp-vis" title="${item.cpHex}">${disp}</span>`;
          }
          return `<span class="cp-inv" title="${escapeHtml(item.label)}">${escapeHtml(item.cpHex)}</span>`;
        }).join('');
      }

      const canaryBanner = $('#zw-canary-alert');
      canaryBanner.classList.add('hidden');

      if (data.decoded && data.decoded.valid) {
        $('#zw-decoded-text').textContent = data.decoded.secretText || '(Rỗng)';
        if (data.decoded.isCanary && data.decoded.canary) {
          const c = data.decoded.canary;
          canaryBanner.innerHTML =
            `<b>🚨 BẮT SỐNG NGUỒN RÒ RỈ NỘI BỘ (CANARY TRAP HIT)!</b><br/>` +
            `• Thủ phạm phát tán bản sao: <b>${escapeHtml(c.recipient)}</b> (Slot #${c.slot})<br/>` +
            `• Mã lô: <code>${escapeHtml(c.batchId)}</code> • Vân tay SHA-256: <code>${escapeHtml(c.fingerprint)}</code> • Cấp lúc: ${escapeHtml(c.taggedAt)}`;
          canaryBanner.classList.remove('hidden');
        }
      } else {
        $('#zw-decoded-text').textContent = `⚠️ ${data.decoded?.error || 'Không có dữ liệu ẩn.'}`;
      }
    } catch (err) {
      showToast('❌ ' + err.message);
    }
  }

  $('#btn-zw-encode').addEventListener('click', runZeroWidthEncode);

  $('#btn-zw-copy').addEventListener('click', async () => {
    const val = $('#zw-output').value;
    if (!val) return;
    await navigator.clipboard.writeText(val);
    showToast('📋 Đã copy câu chứa mực tàng hình vào Clipboard!');
  });

  $('#btn-zw-send-decoder').addEventListener('click', () => {
    $('#zw-decode-input').value = $('#zw-output').value;
    $('#zw-pass-dec').value = $('#zw-pass-enc').value;
    runZeroWidthDecode();
  });

  $('#btn-zw-decode').addEventListener('click', runZeroWidthDecode);

  $('#btn-zw-paste-clear').addEventListener('click', () => {
    $('#zw-decode-input').value = '';
    $('#zw-canary-alert').classList.add('hidden');
    $('#zw-decoded-text').textContent = 'Đã xóa trắng.';
    $('#zw-microscope').innerHTML = '<span class="dim-hint">Các hạt Unicode ẩn sẽ phát sáng tại đây...</span>';
  });

  $('#btn-zw-quick-demo').addEventListener('click', async () => {
    const stego = await runZeroWidthEncode();
    if (stego) {
      $('#zw-decode-input').value = stego;
      $('#zw-pass-dec').value = $('#zw-pass-enc').value;
      await runZeroWidthDecode();
    }
  });

  $('#btn-canary-gen').addEventListener('click', async () => {
    try {
      const recipients = $('#canary-recipients').value
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);

      const data = await apiPost('/api/zerowidth/canary', {
        coverText: $('#canary-cover').value,
        recipients,
        secretNote: $('#canary-note').value,
        password: $('#canary-pass').value,
        mode: 'vs256'
      });

      const listEl = $('#canary-list');
      listEl.innerHTML = '';

      data.items.forEach((item) => {
        const row = document.createElement('div');
        row.className = 'canary-item';
        row.innerHTML = `
          <div>
            <b>👤 ${escapeHtml(item.recipient)}</b>
            <div class="mono-dim">ID: ${escapeHtml(item.fingerprint)} • +${item.stats.invisibleCodePoints} hạt ẩn</div>
          </div>
          <div style="display:flex;gap:6px;">
            <button class="btn-secondary small btn-copy-c">📋 Copy</button>
            <button class="btn-accent-outline small btn-sim-leak">🕵️ Giả lập lộ tin</button>
          </div>
        `;
        row.querySelector('.btn-copy-c').addEventListener('click', async () => {
          await navigator.clipboard.writeText(item.stegoText);
          showToast(`📋 Đã copy bản đóng dấu riêng cho: ${item.recipient}`);
        });
        row.querySelector('.btn-sim-leak').addEventListener('click', () => {
          $('#zw-decode-input').value = item.stegoText;
          $('#zw-pass-dec').value = $('#canary-pass').value;
          runZeroWidthDecode();
          showToast(`🚨 Đang quét bản tin rò rỉ từ ${item.recipient}...`);
        });
        listEl.appendChild(row);
      });

      showToast(`🚨 Đã tạo ${data.count} bản sao y hệt nhau kèm bẫy Canary!`);
    } catch (err) {
      showToast('❌ ' + err.message);
    }
  });

  // ==========================================================================
  // STUDIO 02: AUDIO SPECTROGRAM SYNTHESIZER & WATERFALL SCANNER
  // ==========================================================================

  const paintCanvas = $('#paint-canvas');
  const pCtx = paintCanvas.getContext('2d', { willReadFrequently: true });
  const specCanvas = $('#spec-canvas');
  const sCtx = specCanvas.getContext('2d');

  let lastWavBytes = null;
  let audioCtx = null;
  let activeSourceNode = null;
  let activeMicStream = null;
  let waterfallAnimId = null;

  function clearPaintCanvas() {
    pCtx.fillStyle = '#000000';
    pCtx.fillRect(0, 0, paintCanvas.width, paintCanvas.height);
  }

  function drawAudioPreset(preset) {
    clearPaintCanvas();
    const W = paintCanvas.width;
    const H = paintCanvas.height;
    const txt = ($('#audio-text-input').value || 'SOS 4165').trim();

    pCtx.strokeStyle = '#ffffff';
    pCtx.fillStyle = '#ffffff';
    pCtx.lineWidth = 3;

    if (preset === 'cyber-eye') {
      // Eye contour + iris + custom text
      pCtx.beginPath();
      pCtx.moveTo(22, H / 2);
      pCtx.quadraticCurveTo(90, 14, 158, H / 2);
      pCtx.quadraticCurveTo(90, H - 14, 22, H / 2);
      pCtx.stroke();

      pCtx.beginPath();
      pCtx.arc(90, H / 2, 24, 0, Math.PI * 2);
      pCtx.stroke();

      pCtx.beginPath();
      pCtx.arc(90, H / 2, 9, 0, Math.PI * 2);
      pCtx.fill();

      pCtx.font = '800 32px "JetBrains Mono", monospace';
      pCtx.fillText(txt.slice(0, 10), 174, H / 2 + 11);
    } else if (preset === 'qr-beacon') {
      const drawFinder = (x, y, s) => {
        pCtx.strokeRect(x, y, s, s);
        pCtx.fillRect(x + 6, y + 6, s - 12, s - 12);
      };
      drawFinder(24, 22, 30);
      drawFinder(94, 22, 30);
      drawFinder(24, 92, 30);

      for (let y = 58; y < 116; y += 10) {
        for (let x = 60; x < 122; x += 10) {
          if (((x * 17 + y * 31) % 7) < 4) {
            pCtx.fillRect(x, y, 6, 6);
          }
        }
      }
      pCtx.font = '800 30px "JetBrains Mono", monospace';
      pCtx.fillText(txt.slice(0, 11), 142, H / 2 + 10);
    } else if (preset === 'skull-radar') {
      // Stylized skull / radar reticle
      pCtx.beginPath();
      pCtx.arc(82, 62, 38, Math.PI * 0.85, Math.PI * 0.15, false);
      pCtx.lineTo(104, 118);
      pCtx.lineTo(60, 118);
      pCtx.closePath();
      pCtx.stroke();

      pCtx.beginPath();
      pCtx.arc(68, 62, 9, 0, Math.PI * 2);
      pCtx.arc(96, 62, 9, 0, Math.PI * 2);
      pCtx.fill();

      pCtx.lineWidth = 2;
      for (let sx = 70; sx <= 94; sx += 8) {
        pCtx.beginPath();
        pCtx.moveTo(sx, 102);
        pCtx.lineTo(sx, 118);
        pCtx.stroke();
      }

      pCtx.font = '800 28px "JetBrains Mono", monospace';
      pCtx.fillText(txt || 'APHEX 4165', 142, H / 2 + 10);
    } else {
      // Framed Secret Banner
      pCtx.strokeRect(12, 14, W - 24, H - 28);
      pCtx.font = '800 36px "JetBrains Mono", monospace';
      pCtx.textAlign = 'center';
      pCtx.fillText(txt || 'SECRET 4165', W / 2, H / 2 + 13);
      pCtx.textAlign = 'start';
    }
  }

  // Initialize default spectrogram drawing
  drawAudioPreset('cyber-eye');

  $$('[data-apreset]').forEach((btn) => {
    btn.addEventListener('click', () => {
      $$('[data-apreset]').forEach((b) => b.classList.toggle('active', b === btn));
      drawAudioPreset(btn.dataset.apreset);
    });
  });

  $('#btn-canvas-clear').addEventListener('click', clearPaintCanvas);

  $('#btn-stamp-text').addEventListener('click', () => {
    clearPaintCanvas();
    const txt = ($('#audio-text-input').value || 'HELLO').trim();
    pCtx.strokeStyle = 'rgba(255,255,255,0.75)';
    pCtx.lineWidth = 2;
    pCtx.strokeRect(10, 12, paintCanvas.width - 20, paintCanvas.height - 24);
    pCtx.fillStyle = '#ffffff';
    const fontSize = txt.length > 12 ? 24 : 36;
    pCtx.font = `800 ${fontSize}px "Be Vietnam Pro", "JetBrains Mono", sans-serif`;
    pCtx.textAlign = 'center';
    pCtx.fillText(txt, paintCanvas.width / 2, paintCanvas.height / 2 + fontSize * 0.34);
    pCtx.textAlign = 'start';
  });

  // Upload custom image / QR onto spectrogram canvas
  $('#audio-img-upload').addEventListener('change', (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const img = new Image();
    img.onload = () => {
      clearPaintCanvas();
      const scale = Math.min(paintCanvas.width / img.width, paintCanvas.height / img.height);
      const dw = img.width * scale;
      const dh = img.height * scale;
      const dx = (paintCanvas.width - dw) / 2;
      const dy = (paintCanvas.height - dh) / 2;
      pCtx.drawImage(img, dx, dy, dw, dh);

      // Convert to high-contrast grayscale (and invert if QR dark-on-white)
      const imgData = pCtx.getImageData(0, 0, paintCanvas.width, paintCanvas.height);
      const d = imgData.data;
      const invert = $('#audio-img-invert').checked;
      for (let i = 0; i < d.length; i += 4) {
        const alpha = d[i + 3] / 255;
        let lum = (0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2]) * alpha;
        if (invert && alpha > 0.1) lum = 255 - lum;
        d[i] = d[i + 1] = d[i + 2] = lum;
        d[i + 3] = 255;
      }
      pCtx.putImageData(imgData, 0, 0);
      showToast('🖼️ Đã chuyển ảnh thành ma trận cường độ tần số!');
    };
    img.src = URL.createObjectURL(file);
  });

  // Freehand drawing on #paint-canvas
  let isDrawing = false;
  let eraseMode = false;

  paintCanvas.addEventListener('contextmenu', (e) => e.preventDefault());

  function getCanvasCoords(e) {
    const rect = paintCanvas.getBoundingClientRect();
    return {
      x: ((e.clientX - rect.left) / rect.width) * paintCanvas.width,
      y: ((e.clientY - rect.top) / rect.height) * paintCanvas.height
    };
  }

  paintCanvas.addEventListener('pointerdown', (e) => {
    isDrawing = true;
    eraseMode = e.button === 2 || e.shiftKey;
    const pt = getCanvasCoords(e);
    pCtx.fillStyle = eraseMode ? '#000000' : '#ffffff';
    pCtx.beginPath();
    pCtx.arc(pt.x, pt.y, eraseMode ? 9 : 3.5, 0, Math.PI * 2);
    pCtx.fill();
  });

  window.addEventListener('pointerup', () => {
    isDrawing = false;
  });

  paintCanvas.addEventListener('pointermove', (e) => {
    if (!isDrawing) return;
    const pt = getCanvasCoords(e);
    pCtx.fillStyle = eraseMode ? '#000000' : '#ffffff';
    pCtx.beginPath();
    pCtx.arc(pt.x, pt.y, eraseMode ? 9 : 3.5, 0, Math.PI * 2);
    pCtx.fill();
  });

  // Extract 180 x 72 luminance grid from #paint-canvas
  function extractSynthGrid(outW = 180, outH = 72) {
    const off = document.createElement('canvas');
    off.width = outW;
    off.height = outH;
    const oCtx = off.getContext('2d');
    oCtx.drawImage(paintCanvas, 0, 0, outW, outH);
    const data = oCtx.getImageData(0, 0, outW, outH).data;

    const grid = [];
    for (let y = 0; y < outH; y++) {
      const row = new Array(outW);
      for (let x = 0; x < outW; x++) {
        const idx = (y * outW + x) * 4;
        row[x] = Math.round(0.299 * data[idx] + 0.587 * data[idx + 1] + 0.114 * data[idx + 2]);
      }
      grid.push(row);
    }
    return grid;
  }

  // Spectrogram Color Palettes (0..255 -> [R, G, B])
  function mapPalette(val, palette) {
    const v = Math.max(0, Math.min(255, val)) / 255;
    if (palette === 'phosphor') {
      return [
        Math.round(Math.pow(v, 3) * 140),
        Math.round(Math.pow(v, 1.15) * 255),
        Math.round(Math.pow(v, 2.2) * 120)
      ];
    }
    if (palette === 'cyan') {
      return [
        Math.round(Math.pow(v, 2.6) * 210),
        Math.round(Math.pow(v, 1.35) * 240),
        Math.round(Math.pow(v, 0.9) * 255)
      ];
    }
    // Cyber Magma (Black -> Deep Violet -> Crimson -> Amber -> White)
    if (v < 0.25) {
      const t = v / 0.25;
      return [Math.round(t * 58), Math.round(t * 12), Math.round(t * 98)];
    }
    if (v < 0.55) {
      const t = (v - 0.25) / 0.30;
      return [Math.round(58 + t * 165), Math.round(12 + t * 38), Math.round(98 + t * 20)];
    }
    if (v < 0.82) {
      const t = (v - 0.55) / 0.27;
      return [Math.round(223 + t * 32), Math.round(50 + t * 155), Math.round(118 - t * 70)];
    }
    const t = (v - 0.82) / 0.18;
    return [255, Math.round(205 + t * 50), Math.round(48 + t * 207)];
  }

  function updateFreqAxisLabels(fMin, fMax) {
    const axis = $('#spec-freq-axis');
    const steps = 5;
    const labels = [];
    for (let i = 0; i < steps; i++) {
      const f = fMax - (i / (steps - 1)) * (fMax - fMin);
      labels.push(f >= 1000 ? `${(f / 1000).toFixed(1)}k` : `${Math.round(f)}`);
    }
    axis.innerHTML = labels.map((l) => `<span>${l}</span>`).join('');
  }

  function getSelectedBand() {
    const mode = $('#audio-band').value;
    if (mode === 'stealth') return { freqMin: 13000, freqMax: 19500 };
    if (mode === 'wide') return { freqMin: 500, freqMax: 14000 };
    return { freqMin: 700, freqMax: 9500 };
  }

  function stopActiveAudioScan() {
    if (waterfallAnimId) {
      cancelAnimationFrame(waterfallAnimId);
      waterfallAnimId = null;
    }
    if (activeSourceNode) {
      try { activeSourceNode.stop(); } catch {}
      activeSourceNode = null;
    }
    if (activeMicStream) {
      activeMicStream.getTracks().forEach((t) => t.stop());
      activeMicStream = null;
      $('#btn-mic-toggle').classList.remove('recording');
      $('#btn-mic-toggle').textContent = '🎙️ Bật Micro Thu Sóng Ngoài Đời';
    }
  }

  async function playAndScanWavBytes(wavBytes, fMin, fMax) {
    stopActiveAudioScan();
    if (!audioCtx) {
      audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    if (audioCtx.state === 'suspended') {
      await audioCtx.resume();
    }

    updateFreqAxisLabels(fMin, fMax);

    const copyBuf = wavBytes.buffer.slice(wavBytes.byteOffset, wavBytes.byteOffset + wavBytes.byteLength);
    const audioBuffer = await audioCtx.decodeAudioData(copyBuf);

    const analyser = audioCtx.createAnalyser();
    analyser.fftSize = 4096;
    analyser.smoothingTimeConstant = 0.05;

    const source = audioCtx.createBufferSource();
    source.buffer = audioBuffer;
    source.connect(analyser);
    analyser.connect(audioCtx.destination);
    activeSourceNode = source;

    // Clear spectrogram canvas
    sCtx.fillStyle = '#000000';
    sCtx.fillRect(0, 0, specCanvas.width, specCanvas.height);

    const freqData = new Float32Array(analyser.frequencyBinCount);
    const nyquist = audioCtx.sampleRate / 2;
    const startTime = audioCtx.currentTime;
    const duration = audioBuffer.duration;
    let prevX = 0;

    $('#spec-status').textContent = `🔊 Đang phát & quét phổ tần số trực tiếp (${fMin} Hz – ${fMax} Hz, ${duration.toFixed(1)}s)...`;

    source.start(0);

    function renderFrame() {
      const elapsed = audioCtx.currentTime - startTime;
      const progress = Math.min(1, elapsed / duration);
      const curX = Math.max(prevX + 1, Math.floor(progress * specCanvas.width));
      const colWidth = Math.max(1, curX - prevX);

      analyser.getFloatFrequencyData(freqData);
      const palette = $('#spec-palette').value;
      const H = specCanvas.height;

      const colImg = sCtx.createImageData(colWidth, H);
      const minDb = -88;
      const maxDb = -22;

      for (let y = 0; y < H; y++) {
        const ratio = y / (H - 1);
        const freq = fMax - ratio * (fMax - fMin);
        const bin = Math.max(1, Math.min(freqData.length - 1, Math.round((freq / nyquist) * freqData.length)));
        const db = freqData[bin];
        const norm = Math.max(0, Math.min(1, (db - minDb) / (maxDb - minDb)));
        const [r, g, b] = mapPalette(norm * 255, palette);

        for (let dx = 0; dx < colWidth; dx++) {
          const idx = (y * colWidth + dx) * 4;
          colImg.data[idx] = r;
          colImg.data[idx + 1] = g;
          colImg.data[idx + 2] = b;
          colImg.data[idx + 3] = 255;
        }
      }

      if (prevX < specCanvas.width) {
        sCtx.putImageData(colImg, prevX, 0);
      }
      prevX = curX;

      if (elapsed < duration) {
        waterfallAnimId = requestAnimationFrame(renderFrame);
      } else {
        $('#spec-status').textContent = '✅ Đã quét xong toàn bộ bức tranh ẩn trong sóng âm!';
      }
    }

    waterfallAnimId = requestAnimationFrame(renderFrame);
  }

  async function synthesizeAndPlay() {
    try {
      const { freqMin, freqMax } = getSelectedBand();
      const durationSec = Number($('#audio-duration').value) || 4.5;
      const cloakAmbience = $('#audio-cloak').checked;
      const grid = extractSynthGrid(180, 72);

      $('#spec-status').textContent = '⏳ Đang tổng hợp sóng âm 16-bit PCM .WAV từ bảng vẽ...';

      const data = await apiPost('/api/spectrogram/synthesize', {
        grid,
        durationSec,
        freqMin,
        freqMax,
        cloakAmbience
      });

      lastWavBytes = base64ToUint8(data.wavBase64);
      const wavBlob = new Blob([lastWavBytes], { type: 'audio/wav' });
      const player = $('#wav-player');
      player.src = URL.createObjectURL(wavBlob);
      player.classList.remove('hidden');

      $('#btn-download-wav').disabled = false;
      $('#btn-spec-replay').disabled = false;

      await playAndScanWavBytes(lastWavBytes, freqMin, freqMax);
      showToast('🔊 Đang phát sóng âm & giải mã hình ảnh trên Spectrogram!');
    } catch (err) {
      showToast('❌ ' + err.message);
    }
  }

  $('#btn-synth-wav').addEventListener('click', synthesizeAndPlay);
  $('#btn-audio-quick-demo').addEventListener('click', synthesizeAndPlay);

  $('#btn-spec-replay').addEventListener('click', () => {
    if (!lastWavBytes) return;
    const { freqMin, freqMax } = getSelectedBand();
    playAndScanWavBytes(lastWavBytes, freqMin, freqMax);
  });

  $('#btn-download-wav').addEventListener('click', () => {
    if (!lastWavBytes) return;
    downloadBytes(lastWavBytes, 'spectraveil-secret-audio.wav', 'audio/wav');
  });

  // Instant Offline FFT Scan of any uploaded .WAV file
  $('#wav-upload-scan').addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      stopActiveAudioScan();
      $('#spec-status').textContent = `⚡ Đang giải mã FFT siêu tốc tệp ${file.name}...`;
      const wavBase64 = await fileToBase64(file);
      const { freqMin, freqMax } = getSelectedBand();
      const data = await apiPost('/api/spectrogram/analyze', {
        wavBase64,
        outCols: 270,
        outRows: 128,
        freqMin: 300,
        freqMax: Math.max(12000, freqMax)
      });

      const spec = data.spectrogram;
      updateFreqAxisLabels(spec.freqMin, spec.freqMax);

      const off = document.createElement('canvas');
      off.width = spec.cols;
      off.height = spec.rows;
      const oCtx = off.getContext('2d');
      const img = oCtx.createImageData(spec.cols, spec.rows);
      const palette = $('#spec-palette').value;

      for (let r = 0; r < spec.rows; r++) {
        for (let c = 0; c < spec.cols; c++) {
          const [ red, green, blue ] = mapPalette(spec.pixels[r][c], palette);
          const idx = (r * spec.cols + c) * 4;
          img.data[idx] = red;
          img.data[idx + 1] = green;
          img.data[idx + 2] = blue;
          img.data[idx + 3] = 255;
        }
      }
      oCtx.putImageData(img, 0, 0);
      sCtx.imageSmoothingEnabled = true;
      sCtx.drawImage(off, 0, 0, specCanvas.width, specCanvas.height);

      $('#spec-status').textContent =
        `✅ Đã quét xong ${file.name} (${spec.sampleRate} Hz, ${spec.durationSec}s) bằng thuật toán Cooley-Tukey FFT!`;
      showToast('⚡ Đã dựng toàn bộ ảnh phổ tần số trong tích tắc!');
    } catch (err) {
      showToast('❌ ' + err.message);
    }
  });

  // Live Microphone Air-Gap Waterfall Scanner
  $('#btn-mic-toggle').addEventListener('click', async () => {
    if (activeMicStream) {
      stopActiveAudioScan();
      $('#spec-status').textContent = 'Đã tắt thu sóng Micro.';
      return;
    }

    try {
      stopActiveAudioScan();
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: false,
          noiseSuppression: false,
          autoGainControl: false
        }
      });
      activeMicStream = stream;

      if (!audioCtx) {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      }
      if (audioCtx.state === 'suspended') await audioCtx.resume();

      const src = audioCtx.createMediaStreamSource(stream);
      const analyser = audioCtx.createAnalyser();
      analyser.fftSize = 4096;
      analyser.smoothingTimeConstant = 0.05;
      src.connect(analyser);

      const { freqMin, freqMax } = getSelectedBand();
      updateFreqAxisLabels(fMinSafe(freqMin), freqMax);

      $('#btn-mic-toggle').classList.add('recording');
      $('#btn-mic-toggle').textContent = '⏹️ Dừng Micro';
      $('#spec-status').textContent = '🎙️ Đang thu sóng âm trực tiếp qua Micro — Hãy phát file .WAV từ điện thoại lại gần loa/mic!';

      const freqData = new Float32Array(analyser.frequencyBinCount);
      const nyquist = audioCtx.sampleRate / 2;

      function scrollMicWaterfall() {
        if (!activeMicStream) return;
        // Shift existing spectrogram 2px left
        sCtx.drawImage(specCanvas, 2, 0, specCanvas.width - 2, specCanvas.height, 0, 0, specCanvas.width - 2, specCanvas.height);
        analyser.getFloatFrequencyData(freqData);
        const palette = $('#spec-palette').value;
        const H = specCanvas.height;
        const colImg = sCtx.createImageData(2, H);

        for (let y = 0; y < H; y++) {
          const freq = freqMax - (y / (H - 1)) * (freqMax - freqMin);
          const bin = Math.max(1, Math.min(freqData.length - 1, Math.round((freq / nyquist) * freqData.length)));
          const norm = Math.max(0, Math.min(1, (freqData[bin] + 92) / 62));
          const [r, g, b] = mapPalette(norm * 255, palette);
          for (let dx = 0; dx < 2; dx++) {
            const idx = (y * 2 + dx) * 4;
            colImg.data[idx] = r;
            colImg.data[idx + 1] = g;
            colImg.data[idx + 2] = b;
            colImg.data[idx + 3] = 255;
          }
        }
        sCtx.putImageData(colImg, specCanvas.width - 2, 0);
        waterfallAnimId = requestAnimationFrame(scrollMicWaterfall);
      }
      waterfallAnimId = requestAnimationFrame(scrollMicWaterfall);
    } catch (err) {
      showToast('❌ Không mở được Micro: ' + err.message);
    }
  });

  function fMinSafe(v) { return Number(v) || 700; }

  // ==========================================================================
  // STUDIO 03: CHAMELEON TRIPLE POLYGLOT FORGE (.PNG + .HTML + .ZIP)
  // ==========================================================================

  let customPolyPngBase64 = '';
  let forgedPolyBytes = null;
  const polyZipItems = [
    {
      name: 'mat-lenh-he-thong.txt',
      content: '=== HỒ SƠ MẬT TRONG NGĂN .ZIP ===\nServer Backup: 10.88.14.9\nRecovery Phrase: amber-velvet-orbit-4165',
      isBase64: false
    },
    {
      name: 'secret-blueprint.json',
      content: JSON.stringify({
        project: 'SpectraVeil-Polyglot',
        clearance: 'LEVEL-5',
        coordinates: [10.7769, 106.7009]
      }, null, 2),
      isBase64: false
    }
  ];

  function renderPolyZipBuilder() {
    const wrap = $('#poly-zip-list');
    wrap.innerHTML = '';
    polyZipItems.forEach((item, idx) => {
      const div = document.createElement('div');
      div.className = 'zip-entry-card';
      div.innerHTML = `
        <div class="zip-entry-top">
          <input type="text" class="input small mono zip-name" value="${escapeHtml(item.name)}" />
          <button class="btn-ghost small zip-del" title="Xóa tệp này">✕</button>
        </div>
        ${item.isBase64
          ? `<div class="mono-dim">📦 Tệp nhị phân đính kèm (${Math.round((item.content.length * 3) / 4)} bytes)</div>`
          : `<textarea rows="2" class="textarea mono zip-body">${escapeHtml(item.content)}</textarea>`
        }
      `;
      div.querySelector('.zip-name').addEventListener('input', (e) => {
        item.name = e.target.value;
      });
      const bodyEl = div.querySelector('.zip-body');
      if (bodyEl) {
        bodyEl.addEventListener('input', (e) => {
          item.content = e.target.value;
        });
      }
      div.querySelector('.zip-del').addEventListener('click', () => {
        polyZipItems.splice(idx, 1);
        renderPolyZipBuilder();
      });
      wrap.appendChild(div);
    });
  }

  renderPolyZipBuilder();

  $('#btn-poly-add-file').addEventListener('click', () => {
    polyZipItems.push({
      name: `note-${polyZipItems.length + 1}.txt`,
      content: 'Nội dung tài liệu mật đính kèm thêm...',
      isBase64: false
    });
    renderPolyZipBuilder();
  });

  $('#poly-zip-upload').addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const b64 = await fileToBase64(file);
    polyZipItems.push({
      name: file.name,
      content: b64,
      isBase64: true
    });
    renderPolyZipBuilder();
    showToast(`📎 Đã thêm "${file.name}" vào ngăn nén .ZIP!`);
  });

  $('#poly-custom-png').addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    customPolyPngBase64 = await fileToBase64(file);
    $('#poly-custom-png-name').textContent = `✅ Đang dùng ảnh bìa riêng: ${file.name} (${formatBytes(file.size)})`;
  });

  function renderAnatomySegments(barEl, legendEl, segments, totalBytes) {
    barEl.innerHTML = '';
    legendEl.innerHTML = '';
    segments.forEach((seg) => {
      const pct = Math.max(6, (seg.byteLength / Math.max(1, totalBytes)) * 100);
      const slice = document.createElement('div');
      slice.className = `seg-${seg.kind}`;
      slice.style.width = `${pct}%`;
      slice.title = `${seg.kind}: ${seg.byteLength} bytes`;
      barEl.appendChild(slice);

      const item = document.createElement('div');
      item.innerHTML =
        `<b>[${seg.kind}]</b> <code>0x${seg.start.toString(16).toUpperCase().padStart(4, '0')} → 0x${seg.end.toString(16).toUpperCase().padStart(4, '0')}</code> ` +
        `(${formatBytes(seg.byteLength)}) — ${escapeHtml(seg.label)}`;
      legendEl.appendChild(item);
    });
  }

  async function runForgePolyglot() {
    try {
      const data = await apiPost('/api/polyglot/forge', {
        customPngBase64: customPolyPngBase64,
        coverTheme: $('#poly-theme').value,
        coverLabel: 'Q4 FINANCIAL SUMMARY',
        enableHtmlPersona: $('#poly-enable-html').checked,
        enableZipPersona: $('#poly-enable-zip').checked,
        vaultTitle: $('#poly-vault-title').value,
        secretNote: $('#poly-secret-note').value,
        password: $('#poly-vault-pass').value,
        zipFiles: polyZipItems
      });

      forgedPolyBytes = base64ToUint8(data.fileBase64);

      const pngBlob = new Blob([forgedPolyBytes], { type: 'image/png' });
      $('#poly-preview-img').src = URL.createObjectURL(pngBlob);

      renderAnatomySegments(
        $('#poly-anatomy-bar'),
        $('#poly-anatomy-legend'),
        data.anatomy.segments,
        data.anatomy.totalBytes
      );

      $('#poly-empty-state').classList.add('hidden');
      $('#poly-result-pane').classList.remove('hidden');

      showToast(`🧬 Đã đúc xong File ${data.anatomy.personas.join(' + ')} (${formatBytes(data.anatomy.totalBytes)})!`);
    } catch (err) {
      showToast('❌ ' + err.message);
    }
  }

  $('#btn-forge-polyglot').addEventListener('click', runForgePolyglot);
  $('#btn-poly-quick-demo').addEventListener('click', runForgePolyglot);

  $('#btn-poly-dl-png').addEventListener('click', () => {
    if (!forgedPolyBytes) return;
    downloadBytes(forgedPolyBytes, 'spectraveil-polyglot.png', 'image/png');
    showToast('🖼️ Đã tải về! Hãy thử đổi đuôi sang .html hoặc .zip trên máy của bạn!');
  });

  $('#btn-poly-dl-zip').addEventListener('click', () => {
    if (!forgedPolyBytes) return;
    downloadBytes(forgedPolyBytes, 'spectraveil-polyglot.zip', 'application/zip');
  });

  $('#btn-poly-open-html').addEventListener('click', () => {
    if (!forgedPolyBytes) return;
    const htmlBlob = new Blob([forgedPolyBytes], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(htmlBlob);
    window.open(url, '_blank');
  });

  $('#btn-poly-to-xray').addEventListener('click', async () => {
    if (!forgedPolyBytes) return;
    switchTab('tab-xray');
    await inspectBytesInXray(dataToBase64(forgedPolyBytes), 'spectraveil-polyglot.png');
  });

  function dataToBase64(bytes) {
    let bin = '';
    const CHUNK = 8192;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
    }
    return btoa(bin);
  }

  // ==========================================================================
  // STUDIO 04: PIXEL LSB BIT-PLANE SLICER & BINARY X-RAY FORENSICS
  // ==========================================================================

  const bpCanvas = $('#bitplane-canvas');
  const bpCtx = bpCanvas.getContext('2d');
  let currentLsbPngBase64 = '';
  let currentSourceImageData = null;
  let activePlane = 'rgb';

  function loadPngBase64IntoBitPlaneViewer(b64) {
    return new Promise((resolve) => {
      const img = new Image();
      img.onload = () => {
        bpCanvas.width = img.width;
        bpCanvas.height = img.height;
        bpCtx.drawImage(img, 0, 0);
        currentSourceImageData = bpCtx.getImageData(0, 0, img.width, img.height);
        renderBitPlane(activePlane);
        resolve();
      };
      img.src = 'data:image/png;base64,' + b64;
    });
  }

  function renderBitPlane(plane) {
    activePlane = plane;
    if (!currentSourceImageData) return;

    if (plane === 'rgb') {
      bpCtx.putImageData(currentSourceImageData, 0, 0);
      return;
    }

    const bit = Number(plane) || 0;
    const src = currentSourceImageData.data;
    const out = bpCtx.createImageData(currentSourceImageData.width, currentSourceImageData.height);
    const dst = out.data;

    for (let i = 0; i < src.length; i += 4) {
      const rBit = ((src[i] >> bit) & 1) * 255;
      const gBit = ((src[i + 1] >> bit) & 1) * 255;
      const bBit = ((src[i + 2] >> bit) & 1) * 255;
      dst[i] = rBit;
      dst[i + 1] = gBit;
      dst[i + 2] = bBit;
      dst[i + 3] = 255;
    }
    bpCtx.putImageData(out, 0, 0);
  }

  $$('.bp-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      $$('.bp-btn').forEach((b) => b.classList.toggle('active', b === btn));
      renderBitPlane(btn.dataset.plane);
    });
  });

  $('#lsb-file-input').addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    currentLsbPngBase64 = await fileToBase64(file);
    await loadPngBase64IntoBitPlaneViewer(currentLsbPngBase64);
    $('#lsb-status').textContent = `📂 Đã nạp ảnh ${file.name}. Sẵn sàng giấu tin hoặc trích xuất LSB!`;
  });

  $('#btn-lsb-embed').addEventListener('click', async () => {
    try {
      const data = await apiPost('/api/lsb/embed', {
        pngBase64: currentLsbPngBase64,
        secretText: $('#lsb-secret').value,
        password: $('#lsb-password').value
      });

      currentLsbPngBase64 = data.pngBase64;
      await loadPngBase64IntoBitPlaneViewer(currentLsbPngBase64);
      $('#btn-lsb-download').disabled = false;

      $('#lsb-status').textContent =
        `✅ Đã giấu ${data.stats.usedBytes} bytes vào Bit-0 RGB! Độ nét PSNR = ${data.stats.psnrDb} dB (Chiếm ${data.stats.usagePercent}% sức chứa). Bấm "Bit 0 (LSB!)" bên dưới để soi vệt bit ở cạnh trên cùng!`;
      showToast(`💉 Đã nhúng LSB thành công (PSNR ${data.stats.psnrDb} dB)!`);
    } catch (err) {
      showToast('❌ ' + err.message);
    }
  });

  $('#btn-lsb-extract').addEventListener('click', async () => {
    try {
      if (!currentLsbPngBase64) {
        showToast('⚠️ Hãy tải ảnh hoặc bấm Nhúng Vào Ảnh trước!');
        return;
      }
      const data = await apiPost('/api/lsb/extract', {
        pngBase64: currentLsbPngBase64,
        password: $('#lsb-password').value
      });

      if (data.found && data.secretText !== undefined) {
        $('#lsb-status').textContent = `🔓 GIẢI MÃ LSB THÀNH CÔNG: "${data.secretText}"`;
        showToast('🔓 Đã trích xuất thông điệp ẩn từ hạt điểm ảnh!');
      } else {
        $('#lsb-status').textContent = `⚠️ ${data.error || 'Không tìm thấy tin ẩn LSB.'}`;
      }
    } catch (err) {
      showToast('❌ ' + err.message);
    }
  });

  $('#btn-lsb-download').addEventListener('click', () => {
    if (!currentLsbPngBase64) return;
    downloadBytes(base64ToUint8(currentLsbPngBase64), 'spectraveil-lsb-stego.png', 'image/png');
  });

  async function inspectBytesInXray(fileBase64, filename) {
    try {
      const data = await apiPost('/api/forensics/xray', {
        fileBase64,
        filename,
        password: $('#xray-pass').value
      });

      const r = data.report;
      const box = $('#xray-report');

      const zipHtml = r.zipInfo && r.zipInfo.entries.length > 0
        ? `<div style="margin-top:12px;">
             <div class="field-label">📦 Các tệp ẩn tìm thấy trong ngăn .ZIP nối đuôi (Bấm để bóc riêng từng tệp):</div>
             ${r.zipInfo.entries.map((ent, i) => `
               <div class="xray-zip-item">
                 <div>
                   <b>${escapeHtml(ent.name)}</b>
                   <span class="mono-dim">(${ent.method} • ${ent.uncompressedSize} B • CRC32: ${ent.crcValid ? 'OK' : 'ERR'})</span>
                 </div>
                 <button class="btn-secondary small btn-extract-z" data-zidx="${i}">⬇️ Tải tệp ẩn</button>
               </div>
             `).join('')}
           </div>`
        : '';

      const lsbHtml = r.lsbInfo && r.lsbInfo.found
        ? `<div class="polyglot-alert" style="margin-top:10px;border-color:#22d3ee;">
             🔍 PHÁT HIỆN GÓI TIN ẨN TRONG KÊNH PIXEL LSB (SVLS):<br/>
             <code style="font-weight:400;color:#f8fafc;">${escapeHtml(r.lsbInfo.secretText || r.lsbInfo.error)}</code>
           </div>`
        : '';

      box.innerHTML = `
        ${r.isPolyglot
          ? `<div class="polyglot-alert">🧬 CẢNH BÁO ĐA NHÂN CÁCH (POLYGLOT DETECTED): Tệp này mang đồng thời ${r.personas.length} định dạng sống [${r.personas.join(' + ')}]!</div>`
          : `<div class="mono-status" style="margin-bottom:10px;">Định dạng nhận diện: <b>${r.personas.join(', ') || 'RAW BINARY'}</b></div>`
        }
        <div class="stat-strip">
          <div class="stat-cell"><span class="stat-lbl">Kích thước thực</span><b>${formatBytes(r.totalBytes)}</b></div>
          <div class="stat-cell"><span class="stat-lbl">Độ hỗn loạn Entropy</span><b class="text-cyan">${r.overallEntropy} / 8.0</b></div>
          <div class="stat-cell"><span class="stat-lbl">Số phân vùng Byte</span><b>${r.segments.length} lớp</b></div>
        </div>
        <div class="field-label">Mặt cắt địa chỉ các lớp dữ liệu bên trong tệp:</div>
        <div id="xray-seg-bar" class="anatomy-bar"></div>
        <div id="xray-seg-legend" class="anatomy-legend"></div>
        ${lsbHtml}
        ${zipHtml}
        <div class="field-label" style="margin-top:12px;">SHA-256 &amp; 48 Bytes Đầu Tiên (Magic Header):</div>
        <div class="mono-status" style="word-break:break-all;">
          SHA-256: ${r.sha256}<br/>
          HEX[0..47]: ${r.hexHead}
        </div>
      `;

      renderAnatomySegments($('#xray-seg-bar'), $('#xray-seg-legend'), r.segments, r.totalBytes);

      if (r.zipInfo && r.zipInfo.entries.length > 0) {
        box.querySelectorAll('.btn-extract-z').forEach((btn) => {
          btn.addEventListener('click', () => {
            const ent = r.zipInfo.entries[Number(btn.dataset.zidx)];
            if (ent && ent.base64) {
              downloadBytes(base64ToUint8(ent.base64), ent.name, 'application/octet-stream');
            }
          });
        });
      }

      showToast(`☢️ Đã mổ xẻ xong cấu trúc byte của ${filename}!`);
    } catch (err) {
      showToast('❌ ' + err.message);
    }
  }

  $('#xray-file-input').addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const b64 = await fileToBase64(file);
    await inspectBytesInXray(b64, file.name);
  });
})();
