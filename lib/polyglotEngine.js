/**
 * 🧬 Chameleon Polyglot Engine + PNG LSB Vault + Binary X-Ray Forensics
 * - Triple Polyglot: 1 File duy nhất vừa là ảnh .PNG chuẩn, vừa là Web Vault .HTML khóa mật mã 256-bit,
 *   vừa là kho nén .ZIP chuẩn (đã hiệu chỉnh Offset Central Directory cho Windows Explorer / 7-Zip / PowerShell)
 * - PNG Pixel LSB Steganography (hỗ trợ đủ 5 bộ lọc dòng PNG: None, Sub, Up, Average, Paeth + AES-256-GCM)
 * - Binary Anatomy X-Ray: Mổ xẻ bản đồ cấu trúc byte, đo Shannon Entropy & bóc tách file ẩn
 */

const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { crc32 } = require('./zeroWidth');

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const LSB_MAGIC = Buffer.from('SVLS', 'ascii');

// ============================================================================
// 1. PURE NODE PNG CHUNK PARSER, ENCODER & PROCEDURAL COVER GENERATOR
// ============================================================================

function makePngChunk(typeStr, dataBuf) {
  const typeBuf = Buffer.from(typeStr, 'ascii');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(dataBuf.length, 0);
  const crcInput = Buffer.concat([typeBuf, dataBuf]);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(crcInput), 0);
  return Buffer.concat([lenBuf, typeBuf, dataBuf, crcBuf]);
}

function parsePngChunks(buf) {
  if (!buf || buf.length < 8 || !buf.subarray(0, 8).equals(PNG_SIG)) {
    return null;
  }
  const chunks = [];
  let offset = 8;
  let iendEnd = -1;

  while (offset + 8 <= buf.length) {
    const length = buf.readUInt32BE(offset);
    const type = buf.toString('ascii', offset + 4, offset + 8);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    if (dataEnd + 4 > buf.length) break;

    const data = buf.subarray(dataStart, dataEnd);
    const crc = buf.readUInt32BE(dataEnd);
    chunks.push({
      type,
      length,
      offset,
      totalChunkSize: 12 + length,
      data,
      crc
    });

    offset = dataEnd + 4;
    if (type === 'IEND') {
      iendEnd = offset;
      break;
    }
  }

  if (iendEnd < 0) return null;
  return { chunks, iendEnd };
}

// Tiny 5x7 font helper for drawing crisp labels onto procedural PNG covers
const MINI_FONT = {
  A: [14, 17, 17, 31, 17, 17, 17], B: [30, 17, 17, 30, 17, 17, 30], C: [15, 16, 16, 16, 16, 16, 15],
  D: [30, 17, 17, 17, 17, 17, 30], E: [31, 16, 16, 30, 16, 16, 31], F: [31, 16, 16, 30, 16, 16, 16],
  G: [15, 16, 16, 23, 17, 17, 15], H: [17, 17, 17, 31, 17, 17, 17], I: [31, 4, 4, 4, 4, 4, 31],
  J: [7, 2, 2, 2, 18, 18, 12], K: [17, 18, 20, 24, 20, 18, 17], L: [16, 16, 16, 16, 16, 16, 31],
  M: [17, 27, 21, 21, 17, 17, 17], N: [17, 25, 21, 19, 17, 17, 17], O: [14, 17, 17, 17, 17, 17, 14],
  P: [30, 17, 17, 30, 16, 16, 16], Q: [14, 17, 17, 17, 21, 18, 13], R: [30, 17, 17, 30, 20, 18, 17],
  S: [15, 16, 16, 14, 1, 1, 30], T: [31, 4, 4, 4, 4, 4, 4], U: [17, 17, 17, 17, 17, 17, 14],
  V: [17, 17, 17, 17, 17, 10, 4], W: [17, 17, 17, 21, 21, 27, 17], X: [17, 17, 10, 4, 10, 17, 17],
  Y: [17, 17, 10, 4, 4, 4, 4], Z: [31, 1, 2, 4, 8, 16, 31],
  '0': [14, 17, 19, 21, 25, 17, 14], '1': [4, 12, 4, 4, 4, 4, 14], '2': [14, 17, 1, 6, 8, 16, 31],
  '3': [30, 1, 1, 14, 1, 1, 30], '4': [18, 18, 18, 31, 2, 2, 2], '5': [31, 16, 16, 30, 1, 1, 30],
  '6': [15, 16, 16, 30, 17, 17, 14], '7': [31, 1, 2, 4, 8, 8, 8], '8': [14, 17, 17, 14, 17, 17, 14],
  '9': [14, 17, 17, 15, 1, 1, 14], '-': [0, 0, 0, 31, 0, 0, 0], ':': [0, 4, 4, 0, 4, 4, 0],
  '.': [0, 0, 0, 0, 0, 6, 6], ' ': [0, 0, 0, 0, 0, 0, 0]
};

function drawRgbText(rgb, width, height, text, x0, y0, scale, color) {
  const clean = String(text || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/đ/gi, 'D')
    .toUpperCase();
  let cx = x0;
  for (const ch of clean) {
    const rows = MINI_FONT[ch] || MINI_FONT[' '];
    for (let ry = 0; ry < 7; ry++) {
      const bits = rows[ry];
      for (let rx = 0; rx < 5; rx++) {
        if ((bits >> (4 - rx)) & 1) {
          for (let sy = 0; sy < scale; sy++) {
            for (let sx = 0; sx < scale; sx++) {
              const px = cx + rx * scale + sx;
              const py = y0 + ry * scale + sy;
              if (px >= 0 && px < width && py >= 0 && py < height) {
                const idx = (py * width + px) * 3;
                rgb[idx] = color[0];
                rgb[idx + 1] = color[1];
                rgb[idx + 2] = color[2];
              }
            }
          }
        }
      }
    }
    cx += 6 * scale;
  }
}

function encodeRgbToPng(width, height, rgbBuf, extraTextChunk = null) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // color type 2 = truecolor RGB
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const rowStride = width * 3;
  const rawScanlines = Buffer.alloc((rowStride + 1) * height);
  for (let y = 0; y < height; y++) {
    const dstRow = y * (rowStride + 1);
    rawScanlines[dstRow] = 0; // Filter type 0 (None)
    rgbBuf.copy(rawScanlines, dstRow + 1, y * rowStride, (y + 1) * rowStride);
  }

  const compressed = zlib.deflateSync(rawScanlines, { level: 6 });
  const chunks = [PNG_SIG, makePngChunk('IHDR', ihdr)];
  if (extraTextChunk) {
    chunks.push(extraTextChunk);
  }
  chunks.push(makePngChunk('IDAT', compressed), makePngChunk('IEND', Buffer.alloc(0)));
  return Buffer.concat(chunks);
}

function generateProceduralCoverPng(theme = 'cyber-card', label = 'SPECTRAVEIL ARTIFACT', width = 480, height = 300) {
  const rgb = Buffer.alloc(width * height * 3);

  if (theme === 'finance-chart') {
    // Disguised as a clean Q4 Revenue Analytics Chart
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const idx = (y * width + x) * 3;
        const gridLine = (x % 48 === 0 || y % 40 === 0);
        rgb[idx] = gridLine ? 26 : 15;
        rgb[idx + 1] = gridLine ? 36 : 23;
        rgb[idx + 2] = gridLine ? 56 : 42;
      }
    }
    const bars = [95, 130, 112, 168, 154, 198, 224];
    bars.forEach((bh, i) => {
      const bx = 56 + i * 54;
      const by = height - 42 - bh;
      for (let y = Math.max(20, by); y < height - 42; y++) {
        for (let x = bx; x < bx + 32; x++) {
          const idx = (y * width + x) * 3;
          rgb[idx] = 16;
          rgb[idx + 1] = 185;
          rgb[idx + 2] = 129;
        }
      }
    });
    drawRgbText(rgb, width, height, label || 'Q4 KPI SUMMARY 2026', 28, 18, 2, [226, 232, 240]);
    drawRgbText(rgb, width, height, 'NORMAL PNG REPORT', 28, height - 24, 2, [148, 163, 184]);
  } else if (theme === 'abstract-prism') {
    // Neon Prism Wave
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const idx = (y * width + x) * 3;
        const wave = Math.sin(x * 0.035) * 38 + Math.cos(y * 0.045) * 26;
        const band = Math.abs((y - height / 2) - wave);
        if (band < 18) {
          rgb[idx] = 245;
          rgb[idx + 1] = 158;
          rgb[idx + 2] = 11;
        } else {
          rgb[idx] = Math.min(255, 12 + Math.floor((x / width) * 55));
          rgb[idx + 1] = Math.min(255, 18 + Math.floor((y / height) * 45));
          rgb[idx + 2] = Math.min(255, 48 + Math.floor(((width - x) / width) * 90));
        }
      }
    }
    drawRgbText(rgb, width, height, label || 'PRISM ARCHIVE', 28, 22, 3, [254, 240, 138]);
  } else {
    // Cyber Emblem Postcard
    const cx = width / 2;
    const cy = height / 2;
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const idx = (y * width + x) * 3;
        const d = Math.hypot(x - cx, y - cy);
        const grid = (x % 32 === 0 || y % 32 === 0);
        let r = grid ? 16 : 9;
        let g = grid ? 28 : 14;
        let b = grid ? 46 : 26;

        if (Math.abs(d - 84) < 2.2 || Math.abs(d - 56) < 1.6) {
          r = 6; g = 182; b = 212;
        } else if (d < 22) {
          r = 16; g = 185; b = 129;
        }
        // Border frame
        if (x < 6 || x >= width - 6 || y < 6 || y >= height - 6) {
          r = 20; g = 184; b = 166;
        }
        rgb[idx] = r;
        rgb[idx + 1] = g;
        rgb[idx + 2] = b;
      }
    }
    drawRgbText(rgb, width, height, label || 'SPECTRAVEIL COVER', 24, 20, 2, [103, 232, 249]);
    drawRgbText(rgb, width, height, 'PNG IMAGE SURFACE', 24, height - 28, 2, [52, 211, 153]);
  }

  return encodeRgbToPng(width, height, rgb);
}

// ============================================================================
// 2. STANDALONE 256-BIT ENCRYPTED HTML VAULT GENERATOR (WORKS ON file://!)
// ============================================================================

function encryptVaultPayload(plainUtf8, password) {
  const salt = crypto.randomBytes(16);
  const nonce = crypto.randomBytes(16);
  const passBytes = Buffer.from(String(password), 'utf8');

  // 4,000 rounds iterated SHA-256 key derivation (fast in pure JS on file://, strong key stretching)
  let encKey = crypto.createHash('sha256').update(Buffer.concat([salt, Buffer.from(':ENC:'), passBytes])).digest();
  for (let i = 0; i < 4000; i++) {
    encKey = crypto.createHash('sha256').update(encKey).digest();
  }
  const macKey = crypto.createHash('sha256').update(Buffer.concat([salt, Buffer.from(':MAC:'), encKey])).digest();

  const plainBuf = Buffer.from(plainUtf8, 'utf8');
  const cipherBuf = Buffer.alloc(plainBuf.length);

  const blockCount = Math.ceil(plainBuf.length / 32);
  for (let b = 0; b < blockCount; b++) {
    const ctr = Buffer.alloc(4);
    ctr.writeUInt32BE(b, 0);
    const ks = crypto.createHash('sha256').update(Buffer.concat([encKey, nonce, ctr])).digest();
    const start = b * 32;
    const end = Math.min(plainBuf.length, start + 32);
    for (let i = start; i < end; i++) {
      cipherBuf[i] = plainBuf[i] ^ ks[i - start];
    }
  }

  const mac = crypto.createHash('sha256').update(Buffer.concat([macKey, nonce, cipherBuf])).digest();

  return {
    saltHex: salt.toString('hex'),
    nonceHex: nonce.toString('hex'),
    macHex: mac.toString('hex'),
    cipherB64: cipherBuf.toString('base64')
  };
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function buildStandaloneVaultHtml({
  vaultTitle = 'KÉT SẮT ĐA NHÂN CÁCH SPECTRAVEIL',
  secretNote = '',
  password = '',
  zipFileNames = []
}) {
  const cleanTitle = escapeHtml(vaultTitle);
  const zipSummary = zipFileNames.length > 0
    ? zipFileNames.map((n) => `<li style="margin:4px 0;color:#67e8f9;font-family:monospace;">📦 ${escapeHtml(n)}</li>`).join('')
    : '<li style="color:#94a3b8;">Không đính kèm ngăn .ZIP</li>';

  const hasPassword = String(password || '').trim().length > 0;
  const payloadJson = JSON.stringify({
    note: String(secretNote || ''),
    createdAt: new Date().toISOString(),
    zipFiles: zipFileNames
  });

  const encBundle = hasPassword ? encryptVaultPayload(payloadJson, String(password).trim()) : null;

  // Compact pure-JS SHA-256 so decryption works 100% offline even on local file:/// URLs!
  return `-->
<meta charset="utf-8">
<div id="sv-vault" style="position:fixed;inset:0;z-index:2147483647;background:radial-gradient(circle at 20% 15%,#0f293a 0%,#060913 65%);color:#e2e8f0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;font-size:15px;line-height:1.6;overflow:auto;display:flex;align-items:center;justify-content:center;padding:24px;box-sizing:border-box;">
  <div style="width:100%;max-width:680px;background:rgba(15,23,42,0.92);border:1px solid rgba(56,189,248,0.35);border-radius:16px;padding:28px;box-shadow:0 24px 60px rgba(0,0,0,0.65);">
    <div style="display:inline-block;padding:4px 10px;border-radius:999px;background:rgba(16,185,129,0.16);border:1px solid rgba(16,185,129,0.4);color:#34d399;font-size:12px;font-weight:700;letter-spacing:0.08em;margin-bottom:10px;">TRIPLE POLYGLOT VAULT • PNG + HTML + ZIP</div>
    <h1 style="margin:0 0 8px 0;font-size:22px;color:#f8fafc;">${cleanTitle}</h1>
    <p style="margin:0 0 18px 0;color:#94a3b8;font-size:13.5px;">Bạn vừa đánh thức nhân cách thứ 2 (<b>.HTML</b>) của file ảnh <b>.PNG</b> này. Đổi đuôi file sang <b>.ZIP</b> để lấy thêm các tệp đính kèm bên dưới.</p>
    ${hasPassword ? `
    <div id="sv-lock-box" style="background:#090e1a;border:1px solid #1e293b;border-radius:12px;padding:18px;margin-bottom:16px;">
      <div style="font-weight:600;color:#fbbf24;margin-bottom:8px;">🔒 Nội dung mật đang khóa bằng SHA-256 / Stream-MAC (4.000 vòng)</div>
      <div style="display:flex;gap:8px;">
        <input id="sv-pass" type="password" placeholder="Nhập mật khẩu mở két..." style="flex:1;padding:10px 12px;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#f8fafc;font-size:14px;outline:none;" onkeydown="if(event.key==='Enter')window.__svUnlock()" />
        <button onclick="window.__svUnlock()" style="padding:10px 18px;border-radius:8px;border:0;background:linear-gradient(135deg,#10b981,#06b6d4);color:#04131a;font-weight:700;cursor:pointer;">Giải mã</button>
      </div>
      <div id="sv-err" style="color:#f87171;font-size:13px;margin-top:8px;display:none;"></div>
    </div>
    <div id="sv-secret-view" style="display:none;background:#090e1a;border:1px solid rgba(16,185,129,0.4);border-radius:12px;padding:16px;margin-bottom:16px;">
      <div style="font-size:12px;color:#34d399;font-weight:700;margin-bottom:6px;">✅ NỘI DUNG ĐÃ GIẢI MÃ XÁC THỰC:</div>
      <pre id="sv-secret-text" style="margin:0;white-space:pre-wrap;word-break:break-word;color:#f1f5f9;font-family:Consolas,monospace;font-size:14px;"></pre>
    </div>
    ` : `
    <div style="background:#090e1a;border:1px solid rgba(16,185,129,0.38);border-radius:12px;padding:16px;margin-bottom:16px;">
      <div style="font-size:12px;color:#34d399;font-weight:700;margin-bottom:6px;">📄 THÔNG ĐIỆP BÍ MẬT BÊN TRONG ẢNH:</div>
      <pre style="margin:0;white-space:pre-wrap;word-break:break-word;color:#f1f5f9;font-family:Consolas,monospace;font-size:14px;">${escapeHtml(secretNote)}</pre>
    </div>
    `}
    <div style="background:rgba(2,6,23,0.65);border:1px solid #1e293b;border-radius:10px;padding:12px 16px;">
      <div style="font-size:12px;color:#94a3b8;font-weight:600;margin-bottom:4px;">DANH SÁCH FILE TRONG NGĂN THỨ 3 (ĐỔI ĐUÔI SANG .ZIP ĐỂ GIẢI NÉN):</div>
      <ul style="margin:0;padding-left:18px;font-size:13px;">${zipSummary}</ul>
    </div>
  </div>
</div>
${hasPassword ? `<script>
(function(){
  const BUNDLE = ${JSON.stringify(encBundle)};
  const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  function ror(v,n){return (v>>>n)|(v<<(32-n));}
  function sha256(bytes){
    const l=bytes.length, bitHi=Math.floor((l*8)/0x100000000), bitLo=(l*8)>>>0;
    const padLen=((l+9+63)&~63);
    const m=new Uint8Array(padLen); m.set(bytes); m[l]=0x80;
    const dv=new DataView(m.buffer); dv.setUint32(padLen-8,bitHi); dv.setUint32(padLen-4,bitLo);
    let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    const w=new Uint32Array(64);
    for(let i=0;i<padLen;i+=64){
      for(let t=0;t<16;t++) w[t]=dv.getUint32(i+t*4);
      for(let t=16;t<64;t++){
        const s0=ror(w[t-15],7)^ror(w[t-15],18)^(w[t-15]>>>3);
        const s1=ror(w[t-2],17)^ror(w[t-2],19)^(w[t-2]>>>10);
        w[t]=(w[t-16]+s0+w[t-7]+s1)>>>0;
      }
      let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
      for(let t=0;t<64;t++){
        const S1=ror(e,6)^ror(e,11)^ror(e,25), ch=(e&f)^((~e)&g), t1=(h+S1+ch+K[t]+w[t])>>>0;
        const S0=ror(a,2)^ror(a,13)^ror(a,22), maj=(a&b)^(a&c)^(b&c), t2=(S0+maj)>>>0;
        h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
      }
      h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;h4=(h4+e)>>>0;h5=(h5+f)>>>0;h6=(h6+g)>>>0;h7=(h7+h)>>>0;
    }
    const out=new Uint8Array(32), odv=new DataView(out.buffer);
    [h0,h1,h2,h3,h4,h5,h6,h7].forEach((v,idx)=>odv.setUint32(idx*4,v));
    return out;
  }
  function hexToBytes(h){const a=new Uint8Array(h.length/2);for(let i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a;}
  function bytesToHex(b){return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');}
  function cat(...arrs){const n=arrs.reduce((s,a)=>s+a.length,0),o=new Uint8Array(n);let p=0;for(const a of arrs){o.set(a,p);p+=a.length;}return o;}
  window.__svUnlock = function(){
    const pw = document.getElementById('sv-pass').value.trim();
    const errEl = document.getElementById('sv-err');
    if(!pw){ errEl.textContent='Vui lòng nhập mật khẩu!'; errEl.style.display='block'; return; }
    const enc = new TextEncoder();
    const salt = hexToBytes(BUNDLE.saltHex), nonce = hexToBytes(BUNDLE.nonceHex);
    const bin = atob(BUNDLE.cipherB64), cipher = new Uint8Array(bin.length);
    for(let i=0;i<bin.length;i++) cipher[i]=bin.charCodeAt(i);
    let ek = sha256(cat(salt, enc.encode(':ENC:'), enc.encode(pw)));
    for(let i=0;i<4000;i++) ek = sha256(ek);
    const mk = sha256(cat(salt, enc.encode(':MAC:'), ek));
    const mac = bytesToHex(sha256(cat(mk, nonce, cipher)));
    if(mac !== BUNDLE.macHex){
      errEl.textContent='Sai mật khẩu giải mã két sắt!';
      errEl.style.display='block';
      return;
    }
    const plain = new Uint8Array(cipher.length);
    const blocks = Math.ceil(cipher.length/32);
    for(let b=0;b<blocks;b++){
      const ctr=new Uint8Array(4); new DataView(ctr.buffer).setUint32(0,b);
      const ks=sha256(cat(ek,nonce,ctr));
      for(let i=b*32;i<Math.min(cipher.length,(b+1)*32);i++) plain[i]=cipher[i]^ks[i-b*32];
    }
    const parsed = JSON.parse(new TextDecoder().decode(plain));
    errEl.style.display='none';
    document.getElementById('sv-lock-box').style.display='none';
    document.getElementById('sv-secret-view').style.display='block';
    document.getElementById('sv-secret-text').textContent = parsed.note || '';
  };
})();
</script>` : ''}<plaintext style="display:none">`;
}

// ============================================================================
// 3. OFFSET-ADJUSTED VALID ZIP BUILDER & EXTRACTOR
// ============================================================================

function buildZipAtOffset(files = [], baseOffset = 0) {
  const localParts = [];
  const centralParts = [];
  let relOffset = 0;

  for (const item of files) {
    const safeName = String(item.name || 'secret.txt').replace(/^[\\/]+/, '') || 'secret.txt';
    const nameBuf = Buffer.from(safeName, 'utf8');
    const rawData = Buffer.isBuffer(item.content)
      ? item.content
      : Buffer.from(String(item.content ?? ''), 'utf8');

    const deflated = zlib.deflateRawSync(rawData, { level: 9 });
    const useDeflate = deflated.length < rawData.length;
    const compData = useDeflate ? deflated : rawData;
    const method = useDeflate ? 8 : 0;
    const crc = crc32(rawData);

    // Valid MS-DOS time/date (2026-11-18 09:30:00)
    const dosTime = (9 << 11) | (30 << 5) | 0;
    const dosDate = ((2026 - 1980) << 9) | (11 << 5) | 18;
    const flags = 0x0800; // Bit 11 = UTF-8 filename

    const localHdr = Buffer.alloc(30);
    localHdr.writeUInt32LE(0x04034b50, 0);
    localHdr.writeUInt16LE(20, 4);
    localHdr.writeUInt16LE(flags, 6);
    localHdr.writeUInt16LE(method, 8);
    localHdr.writeUInt16LE(dosTime, 10);
    localHdr.writeUInt16LE(dosDate, 12);
    localHdr.writeUInt32LE(crc, 14);
    localHdr.writeUInt32LE(compData.length, 18);
    localHdr.writeUInt32LE(rawData.length, 22);
    localHdr.writeUInt16LE(nameBuf.length, 26);
    localHdr.writeUInt16LE(0, 28);

    const trueLocalOffset = baseOffset + relOffset;
    localParts.push(localHdr, nameBuf, compData);
    relOffset += localHdr.length + nameBuf.length + compData.length;

    const cdHdr = Buffer.alloc(46);
    cdHdr.writeUInt32LE(0x02014b50, 0);
    cdHdr.writeUInt16LE(20, 4);
    cdHdr.writeUInt16LE(20, 6);
    cdHdr.writeUInt16LE(flags, 8);
    cdHdr.writeUInt16LE(method, 10);
    cdHdr.writeUInt16LE(dosTime, 12);
    cdHdr.writeUInt16LE(dosDate, 14);
    cdHdr.writeUInt32LE(crc, 16);
    cdHdr.writeUInt32LE(compData.length, 20);
    cdHdr.writeUInt32LE(rawData.length, 24);
    cdHdr.writeUInt16LE(nameBuf.length, 28);
    cdHdr.writeUInt16LE(0, 30);
    cdHdr.writeUInt16LE(0, 32);
    cdHdr.writeUInt16LE(0, 34);
    cdHdr.writeUInt16LE(0, 36);
    cdHdr.writeUInt32LE(0, 38);
    cdHdr.writeUInt32LE(trueLocalOffset >>> 0, 42); // Exact true byte offset from start of Polyglot!

    centralParts.push(cdHdr, nameBuf);
  }

  const cdBuf = Buffer.concat(centralParts);
  const trueCdOffset = baseOffset + relOffset;

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(trueCdOffset >>> 0, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, cdBuf, eocd]);
}

function extractZipFromBuffer(buf) {
  if (!buf || buf.length < 22) return null;

  // Search backwards for End of Central Directory (0x06054b50)
  const minPos = Math.max(0, buf.length - 65557);
  let eocdPos = -1;
  for (let i = buf.length - 22; i >= minPos; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocdPos = i;
      break;
    }
  }
  if (eocdPos < 0) return null;

  const entryCount = buf.readUInt16LE(eocdPos + 10);
  const cdSize = buf.readUInt32LE(eocdPos + 12);
  const cdOffset = buf.readUInt32LE(eocdPos + 16);

  if (cdOffset + cdSize > buf.length) return null;

  const entries = [];
  let ptr = cdOffset;
  let minLocalOffset = cdOffset;

  for (let i = 0; i < entryCount && ptr + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(ptr) !== 0x02014b50) break;
    const method = buf.readUInt16LE(ptr + 10);
    const expectedCrc = buf.readUInt32LE(ptr + 16);
    const compSize = buf.readUInt32LE(ptr + 20);
    const uncompSize = buf.readUInt32LE(ptr + 24);
    const nameLen = buf.readUInt16LE(ptr + 28);
    const extraLen = buf.readUInt16LE(ptr + 30);
    const commentLen = buf.readUInt16LE(ptr + 32);
    const localOffset = buf.readUInt32LE(ptr + 42);

    if (localOffset < minLocalOffset) minLocalOffset = localOffset;
    const name = buf.toString('utf8', ptr + 46, ptr + 46 + nameLen);

    let extractedBuffer = null;
    let crcValid = false;

    if (localOffset + 30 <= buf.length && buf.readUInt32LE(localOffset) === 0x04034b50) {
      const lNameLen = buf.readUInt16LE(localOffset + 26);
      const lExtraLen = buf.readUInt16LE(localOffset + 28);
      const dataStart = localOffset + 30 + lNameLen + lExtraLen;
      const dataEnd = dataStart + compSize;
      if (dataEnd <= buf.length) {
        const compSlice = buf.subarray(dataStart, dataEnd);
        try {
          extractedBuffer = method === 8 ? zlib.inflateRawSync(compSlice) : Buffer.from(compSlice);
          crcValid = crc32(extractedBuffer) === expectedCrc;
        } catch {
          extractedBuffer = null;
        }
      }
    }

    entries.push({
      name,
      method: method === 8 ? 'DEFLATE' : 'STORE',
      compressedSize: compSize,
      uncompressedSize: uncompSize,
      localOffset,
      crcValid,
      textPreview: extractedBuffer ? extractedBuffer.subarray(0, 500).toString('utf8') : null,
      base64: extractedBuffer ? extractedBuffer.toString('base64') : null
    });

    ptr += 46 + nameLen + extraLen + commentLen;
  }

  return {
    zipStartOffset: minLocalOffset,
    centralDirectoryOffset: cdOffset,
    eocdOffset: eocdPos,
    entryCount: entries.length,
    entries
  };
}

// ============================================================================
// 4. FORGE TRIPLE POLYGLOT (.PNG + .HTML + .ZIP)
// ============================================================================

function injectCloakIntoPng(pngBuf, includeHtmlCloak) {
  const parsed = parsePngChunks(pngBuf);
  if (!parsed) {
    throw new Error('Dữ liệu ảnh bìa không phải định dạng .PNG hợp lệ.');
  }

  const outChunks = [PNG_SIG];
  const cloakCss = 'Comment\0<style>html,body{margin:0!important;padding:0!important;font-size:0!important;line-height:0!important;color:transparent!important;background:#060913!important;overflow:hidden!important}body>*:not(#sv-vault){display:none!important}</style><!--';

  for (const ch of parsed.chunks) {
    // Strip any old Comment cloak chunk if re-forging
    if (ch.type === 'tEXt' && ch.data.subarray(0, 8).toString('ascii') === 'Comment\0') {
      continue;
    }
    const rawChunk = pngBuf.subarray(ch.offset, ch.offset + ch.totalChunkSize);
    outChunks.push(rawChunk);
    if (ch.type === 'IHDR' && includeHtmlCloak) {
      outChunks.push(makePngChunk('tEXt', Buffer.from(cloakCss, 'ascii')));
    }
  }

  return Buffer.concat(outChunks);
}

function forgePolyglotFile({
  customPngBuffer = null,
  coverTheme = 'cyber-card',
  coverLabel = 'SPECTRAVEIL ARTIFACT',
  enableHtmlPersona = true,
  enableZipPersona = true,
  vaultTitle = 'KÉT SẮT ĐA NHÂN CÁCH SPECTRAVEIL',
  secretNote = 'Tài liệu Mật cấp độ Alpha — Ẩn bên trong ảnh .PNG!',
  password = '',
  zipFiles = []
}) {
  const rawCover = customPngBuffer && customPngBuffer.length > 0
    ? customPngBuffer
    : generateProceduralCoverPng(coverTheme, coverLabel);

  const pngSegment = injectCloakIntoPng(rawCover, Boolean(enableHtmlPersona));

  const effectiveZipFiles = enableZipPersona
    ? (zipFiles.length > 0
      ? zipFiles
      : [
          {
            name: 'README-BI-MAT.txt',
            content: `=== KHO LƯU TRỮ NGẦM POLYGLOT ===\nTạo lúc: ${new Date().toISOString()}\nGhi chú: ${secretNote}\n`
          },
          {
            name: 'config-secret.json',
            content: JSON.stringify({
              protocol: 'SpectraVeil-Polyglot-v1',
              personas: ['PNG', enableHtmlPersona ? 'HTML5-Vault' : null, 'ZIP-Archive'].filter(Boolean),
              classifiedNote: secretNote
            }, null, 2)
          }
        ])
    : [];

  const htmlSegment = enableHtmlPersona
    ? Buffer.from(
        buildStandaloneVaultHtml({
          vaultTitle,
          secretNote,
          password,
          zipFileNames: effectiveZipFiles.map((f) => f.name)
        }),
        'utf8'
      )
    : Buffer.alloc(0);

  const zipBaseOffset = pngSegment.length + htmlSegment.length;
  const zipSegment = enableZipPersona && effectiveZipFiles.length > 0
    ? buildZipAtOffset(effectiveZipFiles, zipBaseOffset)
    : Buffer.alloc(0);

  const finalBuffer = Buffer.concat([pngSegment, htmlSegment, zipSegment]);

  return {
    buffer: finalBuffer,
    anatomy: {
      totalBytes: finalBuffer.length,
      personas: [
        'PNG',
        ...(enableHtmlPersona ? ['HTML'] : []),
        ...(enableZipPersona && zipSegment.length > 0 ? ['ZIP'] : [])
      ],
      segments: [
        {
          kind: 'PNG',
          label: 'Ảnh Bìa Chuẩn PNG (IHDR → tEXt Cloak → IDAT → IEND)',
          start: 0,
          end: pngSegment.length,
          byteLength: pngSegment.length
        },
        ...(htmlSegment.length > 0
          ? [{
              kind: 'HTML',
              label: password
                ? 'Két Sắt Web HTML5 (Khóa Mật Mã SHA-256 Stream-MAC)'
                : 'Ứng Dụng Web HTML5 Bí Mật (Mở trực tiếp khi đổi sang .html)',
              start: pngSegment.length,
              end: pngSegment.length + htmlSegment.length,
              byteLength: htmlSegment.length
            }]
          : []),
        ...(zipSegment.length > 0
          ? [{
              kind: 'ZIP',
              label: `Kho Nén .ZIP Chuẩn Offset (${effectiveZipFiles.length} tệp đính kèm)`,
              start: zipBaseOffset,
              end: finalBuffer.length,
              byteLength: zipSegment.length
            }]
          : [])
      ]
    }
  };
}

// ============================================================================
// 5. PNG PIXEL LSB STEGANOGRAPHY (ALL 5 PNG ROW FILTERS + AES-256-GCM)
// ============================================================================

function paethPredictor(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  if (pb <= pc) return b;
  return c;
}

function decodePngPixels(pngBuf) {
  const parsed = parsePngChunks(pngBuf);
  if (!parsed) throw new Error('File không phải ảnh .PNG hợp lệ.');

  const ihdrChunk = parsed.chunks.find((c) => c.type === 'IHDR');
  if (!ihdrChunk) throw new Error('Thiếu IHDR chunk trong PNG.');

  const width = ihdrChunk.data.readUInt32BE(0);
  const height = ihdrChunk.data.readUInt32BE(4);
  const bitDepth = ihdrChunk.data[8];
  const colorType = ihdrChunk.data[9];
  const interlace = ihdrChunk.data[12];

  if (bitDepth !== 8 || (colorType !== 2 && colorType !== 6) || interlace !== 0) {
    throw new Error('LSB Engine hỗ trợ ảnh PNG 8-bit RGB/RGBA không đan dòng (Non-interlaced).');
  }

  const channels = colorType === 6 ? 4 : 3;
  const bpp = channels;
  const stride = width * channels;

  const idatData = Buffer.concat(parsed.chunks.filter((c) => c.type === 'IDAT').map((c) => c.data));
  const raw = zlib.inflateSync(idatData);

  if (raw.length < height * (stride + 1)) {
    throw new Error('Dữ liệu dòng quét IDAT không đủ kích thước.');
  }

  const pixels = Buffer.alloc(height * stride);

  for (let y = 0; y < height; y++) {
    const filterType = raw[y * (stride + 1)];
    const srcStart = y * (stride + 1) + 1;
    const dstStart = y * stride;
    const prevStart = (y - 1) * stride;

    for (let x = 0; x < stride; x++) {
      const filt = raw[srcStart + x];
      const left = x >= bpp ? pixels[dstStart + x - bpp] : 0;
      const up = y > 0 ? pixels[prevStart + x] : 0;
      const upLeft = (y > 0 && x >= bpp) ? pixels[prevStart + x - bpp] : 0;

      let recon = filt;
      if (filterType === 1) recon = (filt + left) & 0xff;
      else if (filterType === 2) recon = (filt + up) & 0xff;
      else if (filterType === 3) recon = (filt + ((left + up) >> 1)) & 0xff;
      else if (filterType === 4) recon = (filt + paethPredictor(left, up, upLeft)) & 0xff;

      pixels[dstStart + x] = recon;
    }
  }

  return { width, height, channels, colorType, pixels };
}

function encodePixelsToPng(width, height, channels, pixels) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = channels === 4 ? 6 : 2;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const stride = width * channels;
  const raw = Buffer.alloc(height * (stride + 1));
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0;
    pixels.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }

  const compressed = zlib.deflateSync(raw, { level: 6 });
  return Buffer.concat([
    PNG_SIG,
    makePngChunk('IHDR', ihdr),
    makePngChunk('IDAT', compressed),
    makePngChunk('IEND', Buffer.alloc(0))
  ]);
}

function embedPngLsb({ pngBuffer = null, secretText = '', password = '' }) {
  const srcPng = pngBuffer && pngBuffer.length > 0
    ? pngBuffer
    : generateProceduralCoverPng('cyber-card', 'LSB VAULT IMAGE');

  const decoded = decodePngPixels(srcPng);
  const { width, height, channels, pixels } = decoded;
  const stegoPixels = Buffer.from(pixels);

  const rawBody = zlib.deflateRawSync(Buffer.from(String(secretText || ''), 'utf8'), { level: 9 });
  const hasPass = String(password || '').trim().length > 0;

  let bodyPacket;
  let flags = 0;
  if (hasPass) {
    flags = 1;
    const salt = crypto.randomBytes(8);
    const iv = crypto.randomBytes(12);
    const key = crypto.scryptSync(String(password).trim(), salt, 32, { N: 16384, r: 8, p: 1 });
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(rawBody), cipher.final()]);
    const tag = cipher.getAuthTag();
    bodyPacket = Buffer.concat([salt, iv, tag, ct]);
  } else {
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crc32(rawBody), 0);
    bodyPacket = Buffer.concat([crcBuf, rawBody]);
  }

  // Header: SVLS (4) + flags (1) + bodyLength (4) + bodyPacket
  const header = Buffer.alloc(9);
  LSB_MAGIC.copy(header, 0);
  header[4] = flags;
  header.writeUInt32BE(bodyPacket.length, 5);
  const fullPayload = Buffer.concat([header, bodyPacket]);

  const totalBitsNeeded = fullPayload.length * 8;
  const maxRgbChannels = width * height * 3;
  if (totalBitsNeeded > maxRgbChannels) {
    throw new Error(`Dung lượng tin mật (${fullPayload.length} bytes) vượt sức chứa LSB 1-bit của ảnh (${Math.floor(maxRgbChannels / 8)} bytes).`);
  }

  let bitIdx = 0;
  let mseSum = 0;
  const totalSamples = width * height * channels;

  for (let i = 0; i < totalSamples && bitIdx < totalBitsNeeded; i++) {
    // Skip Alpha channel in RGBA so transparency never shifts
    if (channels === 4 && (i % 4 === 3)) continue;
    const bytePos = bitIdx >> 3;
    const bitShift = 7 - (bitIdx & 7);
    const bit = (fullPayload[bytePos] >> bitShift) & 1;

    const orig = stegoPixels[i];
    const modified = (orig & 0xfe) | bit;
    const diff = orig - modified;
    mseSum += diff * diff;
    stegoPixels[i] = modified;
    bitIdx++;
  }

  const mse = mseSum / (width * height * 3);
  const psnrDb = mse === 0 ? 99.9 : Number((10 * Math.log10((255 * 255) / mse)).toFixed(2));

  return {
    pngBuffer: encodePixelsToPng(width, height, channels, stegoPixels),
    stats: {
      width,
      height,
      capacityBytes: Math.floor(maxRgbChannels / 8),
      usedBytes: fullPayload.length,
      usagePercent: Number(((totalBitsNeeded / maxRgbChannels) * 100).toFixed(2)),
      psnrDb,
      encrypted: hasPass
    }
  };
}

function extractPngLsb({ pngBuffer, password = '' }) {
  const decoded = decodePngPixels(pngBuffer);
  const { width, height, channels, pixels } = decoded;
  const totalSamples = width * height * channels;

  const readBytesFromBits = (numBytes, startBitOffset = 0) => {
    const out = Buffer.alloc(numBytes);
    const endBit = startBitOffset + numBytes * 8;
    let rgbIdx = 0;

    for (let i = 0; i < totalSamples && rgbIdx < endBit; i++) {
      if (channels === 4 && (i % 4 === 3)) continue;
      if (rgbIdx >= startBitOffset) {
        const rel = rgbIdx - startBitOffset;
        const bit = pixels[i] & 1;
        out[rel >> 3] = (out[rel >> 3] << 1) | bit;
      }
      rgbIdx++;
    }
    return out;
  };

  if (width * height * 3 < 72) {
    return { found: false, error: 'Ảnh quá nhỏ để chứa gói tin LSB.' };
  }

  const hdr = readBytesFromBits(9, 0);
  if (!hdr.subarray(0, 4).equals(LSB_MAGIC)) {
    return { found: false, error: 'Không phát hiện chữ ký giấu tin LSB (SVLS) trên kênh Bit-0 của ảnh.' };
  }

  const flags = hdr[4];
  const bodyLen = hdr.readUInt32BE(5);
  const maxBytes = Math.floor((width * height * 3) / 8) - 9;
  if (bodyLen <= 0 || bodyLen > maxBytes) {
    return { found: false, error: 'Độ dài gói tin LSB không hợp lệ.' };
  }

  const body = readBytesFromBits(bodyLen, 72);
  let compressedPayload;

  if (flags & 1) {
    const cleanPass = String(password || '').trim();
    if (!cleanPass) {
      return { found: true, encrypted: true, requiresPassword: true, error: 'Ảnh chứa gói tin LSB khóa bằng AES-256-GCM. Hãy nhập mật khẩu!' };
    }
    try {
      const salt = body.subarray(0, 8);
      const iv = body.subarray(8, 20);
      const tag = body.subarray(20, 36);
      const ct = body.subarray(36);
      const key = crypto.scryptSync(cleanPass, salt, 32, { N: 16384, r: 8, p: 1 });
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);
      compressedPayload = Buffer.concat([decipher.update(ct), decipher.final()]);
    } catch {
      return { found: true, encrypted: true, requiresPassword: true, wrongPassword: true, error: 'Sai mật khẩu giải mã PNG LSB!' };
    }
  } else {
    const expectedCrc = body.readUInt32BE(0);
    compressedPayload = body.subarray(4);
    if (crc32(compressedPayload) !== expectedCrc) {
      return { found: false, error: 'Sai lệch mã kiểm tra CRC-32 trong dữ liệu LSB.' };
    }
  }

  const secretText = zlib.inflateRawSync(compressedPayload).toString('utf8');
  return {
    found: true,
    encrypted: Boolean(flags & 1),
    secretText,
    byteLength: bodyLen
  };
}

// ============================================================================
// 6. UNIVERSAL BINARY ANATOMY X-RAY SCANNER
// ============================================================================

function computeShannonEntropy(buf) {
  if (!buf || buf.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < buf.length; i++) counts[buf[i]]++;
  let entropy = 0;
  const len = buf.length;
  for (let i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      const p = counts[i] / len;
      entropy -= p * Math.log2(p);
    }
  }
  return Number(entropy.toFixed(3));
}

function inspectBinaryAnatomy(buf, filename = 'unknown.bin', password = '') {
  const segments = [];
  const personas = [];
  let pngInfo = null;
  let lsbInfo = null;

  const parsedPng = parsePngChunks(buf);
  if (parsedPng) {
    personas.push('PNG');
    const ihdr = parsedPng.chunks.find((c) => c.type === 'IHDR');
    pngInfo = {
      width: ihdr ? ihdr.data.readUInt32BE(0) : 0,
      height: ihdr ? ihdr.data.readUInt32BE(4) : 0,
      chunkTypes: parsedPng.chunks.map((c) => c.type),
      iendOffset: parsedPng.iendEnd,
      trailingBytes: buf.length - parsedPng.iendEnd
    };
    segments.push({
      kind: 'PNG',
      label: `Cấu trúc PNG (${pngInfo.width}x${pngInfo.height}px • ${parsedPng.chunks.length} chunks)`,
      start: 0,
      end: parsedPng.iendEnd,
      byteLength: parsedPng.iendEnd,
      entropy: computeShannonEntropy(buf.subarray(0, parsedPng.iendEnd))
    });

    try {
      lsbInfo = extractPngLsb({ pngBuffer: buf.subarray(0, parsedPng.iendEnd), password });
    } catch {
      lsbInfo = { found: false };
    }
  } else if (buf.length >= 12 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WAVE') {
    personas.push('WAV');
    segments.push({
      kind: 'WAV',
      label: ' Luồng Âm Thanh RIFF WAVE PCM (.wav)',
      start: 0,
      end: buf.length,
      byteLength: buf.length,
      entropy: computeShannonEntropy(buf)
    });
  }

  const zipInfo = extractZipFromBuffer(buf);

  // Detect embedded HTML Vault between PNG IEND and ZIP start (or EOF)
  const tailStart = parsedPng ? parsedPng.iendEnd : 0;
  const tailEnd = zipInfo ? zipInfo.zipStartOffset : buf.length;

  if (tailEnd > tailStart) {
    const midSlice = buf.subarray(tailStart, tailEnd);
    const midStr = midSlice.toString('utf8');
    if (midStr.includes('<div') || midStr.includes('<html') || midStr.includes('sv-vault') || midStr.includes('<script')) {
      personas.push('HTML');
      segments.push({
        kind: 'HTML',
        label: midStr.includes('sv-lock-box')
          ? 'Két Sắt Web HTML5 Đã Khóa Mật Mã (256-bit)'
          : 'Ứng Dụng / Trang Web HTML5 Ẩn Sau IEND',
        start: tailStart,
        end: tailEnd,
        byteLength: tailEnd - tailStart,
        entropy: computeShannonEntropy(midSlice)
      });
    } else if (parsedPng) {
      segments.push({
        kind: 'OVERLAY_DATA',
        label: 'Dữ Liệu Ghép Nối Thêm Phía Sau IEND (Overlay Bytes)',
        start: tailStart,
        end: tailEnd,
        byteLength: tailEnd - tailStart,
        entropy: computeShannonEntropy(midSlice)
      });
    }
  }

  if (zipInfo && zipInfo.entryCount > 0) {
    personas.push('ZIP');
    segments.push({
      kind: 'ZIP',
      label: `Kho Lưu Trữ .ZIP (${zipInfo.entryCount} tệp • EOCD @ 0x${zipInfo.eocdOffset.toString(16).toUpperCase()})`,
      start: zipInfo.zipStartOffset,
      end: buf.length,
      byteLength: buf.length - zipInfo.zipStartOffset,
      entropy: computeShannonEntropy(buf.subarray(zipInfo.zipStartOffset))
    });
  }

  if (segments.length === 0) {
    segments.push({
      kind: 'RAW',
      label: 'Dữ Liệu Nhị Phân / Văn Bản Thường',
      start: 0,
      end: buf.length,
      byteLength: buf.length,
      entropy: computeShannonEntropy(buf)
    });
  }

  const hexHead = Array.from(buf.subarray(0, 48))
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(' ');

  return {
    filename,
    totalBytes: buf.length,
    overallEntropy: computeShannonEntropy(buf),
    sha256: crypto.createHash('sha256').update(buf).digest('hex'),
    isPolyglot: personas.length >= 2,
    personas,
    segments,
    pngInfo,
    lsbInfo,
    zipInfo,
    hexHead
  };
}

module.exports = {
  generateProceduralCoverPng,
  forgePolyglotFile,
  extractZipFromBuffer,
  embedPngLsb,
  extractPngLsb,
  inspectBinaryAnatomy
};
