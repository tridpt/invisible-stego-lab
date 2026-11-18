/**
 * 🕵️‍♂️🔊 SpectraVeil Lab — Phòng Thí Nghiệm Giấu Tin Vô Hình (Port 4165)
 * 4 Trạm Kỹ Thuật Giấu Tin "Trick-Trick" Hoạt Động Ở Cấp Độ Nhị Phân Thực:
 *   1. Zero-Width & Canary Leak Trap (Unicode Variation Selectors 8-bit/char + AES-256-GCM + Bẫy Rò Rỉ Nội Bộ)
 *   2. Audio Spectrogram Lab (Vẽ Tranh / Chữ Mật / Mã QR Vào Sóng Âm .WAV + Máy Soi Phổ Thác Nước Realtime)
 *   3. Chameleon Triple Polyglot Forge (1 File = Ảnh .PNG + Két Web .HTML Khóa 256-bit + Kho Nén .ZIP Chuẩn Offset)
 *   4. Forensic Bit-Plane & Binary X-Ray (Giấu Tin Pixel LSB PSNR > 51dB + Cắt Lớp Bit 0..7 + Mổ Xẻ Byte Đa Nhân Cách)
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');

const {
  encodeZeroWidth,
  inspectAndDecodeZeroWidth,
  generateCanaryBatch
} = require('./lib/zeroWidth');

const {
  buildPresetGrid,
  synthesizeSpectrogramWav,
  decodeWavToSpectrogram
} = require('./lib/spectrogramWav');

const {
  forgePolyglotFile,
  embedPngLsb,
  extractPngLsb,
  inspectBinaryAnatomy
} = require('./lib/polyglotEngine');

const PORT = Number(process.env.PORT || 4165);
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_BODY_BYTES = 32 * 1024 * 1024; // 32 MB for PNG / WAV / ZIP uploads

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.wav': 'audio/wav',
  '.ico': 'image/x-icon'
};

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(body);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;

    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error('Dữ liệu gửi lên vượt quá giới hạn 32 MB.'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error('Định dạng JSON gửi lên không hợp lệ.'));
      }
    });

    req.on('error', reject);
  });
}

function stripDataUrlPrefix(b64) {
  if (!b64 || typeof b64 !== 'string') return '';
  const commaIdx = b64.indexOf(',');
  return commaIdx !== -1 && b64.startsWith('data:') ? b64.slice(commaIdx + 1) : b64;
}

function sanitizeGrid(rawGrid) {
  if (!Array.isArray(rawGrid) || rawGrid.length < 8 || rawGrid.length > 256) {
    return null;
  }
  const width = Array.isArray(rawGrid[0]) ? rawGrid[0].length : 0;
  if (width < 8 || width > 512) return null;

  return rawGrid.map((row) => {
    const arr = new Uint8Array(width);
    for (let x = 0; x < width; x++) {
      arr[x] = Math.max(0, Math.min(255, Number(row[x]) || 0));
    }
    return arr;
  });
}

function createAppServer() {
  return http.createServer(async (req, res) => {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      });
      res.end();
      return;
    }

    const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);
    const pathname = parsedUrl.pathname;

    try {
      // ----------------------------------------------------------------------
      // 1. HEALTH CHECK
      // ----------------------------------------------------------------------
      if (req.method === 'GET' && pathname === '/api/health') {
        return sendJson(res, 200, {
          ok: true,
          app: 'SpectraVeil Lab — Phòng Thí Nghiệm Giấu Tin Vô Hình',
          port: PORT,
          modules: [
            'zero-width-vs256-aes',
            'canary-leak-trap',
            'audio-spectrogram-wav-synth',
            'triple-polyglot-png-html-zip',
            'png-lsb-bitplane-xray'
          ],
          uptimeSec: Math.round(process.uptime())
        });
      }

      // ----------------------------------------------------------------------
      // 2. STUDIO 1: ZERO-WIDTH & CANARY LEAK TRAP
      // ----------------------------------------------------------------------
      if (req.method === 'POST' && pathname === '/api/zerowidth/encode') {
        const body = await readJsonBody(req);
        if (!String(body.secretText ?? '').trim()) {
          return sendJson(res, 400, { ok: false, error: 'Vui lòng nhập nội dung bí mật cần giấu.' });
        }
        const result = encodeZeroWidth({
          coverText: body.coverText,
          secretText: body.secretText,
          password: body.password || '',
          mode: body.mode || 'vs256'
        });
        return sendJson(res, 200, { ok: true, ...result });
      }

      if (req.method === 'POST' && pathname === '/api/zerowidth/decode') {
        const body = await readJsonBody(req);
        const result = inspectAndDecodeZeroWidth({
          stegoText: body.stegoText || '',
          password: body.password || ''
        });
        return sendJson(res, 200, { ok: true, ...result });
      }

      if (req.method === 'POST' && pathname === '/api/zerowidth/canary') {
        const body = await readJsonBody(req);
        const recipients = Array.isArray(body.recipients) ? body.recipients : [];
        if (recipients.length === 0) {
          return sendJson(res, 400, { ok: false, error: 'Vui lòng nhập ít nhất 1 người nhận để gắn bẫy rò rỉ Canary.' });
        }
        const result = generateCanaryBatch({
          coverText: body.coverText || 'Thông báo mật: Kế hoạch ra mắt sản phẩm Quý 4.',
          recipients,
          secretNote: body.secretNote || 'Bản phát hành nội bộ có đánh dấu nguồn rò rỉ.',
          password: body.password || '',
          mode: body.mode || 'vs256'
        });
        return sendJson(res, 200, { ok: true, ...result });
      }

      // ----------------------------------------------------------------------
      // 3. STUDIO 2: AUDIO SPECTROGRAM SYNTHESIZER & FFT SCANNER
      // ----------------------------------------------------------------------
      if (req.method === 'POST' && pathname === '/api/spectrogram/synthesize') {
        const body = await readJsonBody(req);
        const customGrid = sanitizeGrid(body.grid);
        const grid = customGrid || buildPresetGrid(
          body.presetId || 'cyber-eye',
          body.customText || 'CODE: 4165',
          Number(body.width) || 180,
          Number(body.height) || 72
        );

        const { wavBuffer, meta } = synthesizeSpectrogramWav({
          grid,
          durationSec: body.durationSec ?? 4.0,
          freqMin: body.freqMin ?? 800,
          freqMax: body.freqMax ?? 9500,
          cloakAmbience: Boolean(body.cloakAmbience)
        });

        return sendJson(res, 200, {
          ok: true,
          wavBase64: wavBuffer.toString('base64'),
          meta
        });
      }

      if (req.method === 'POST' && pathname === '/api/spectrogram/analyze') {
        const body = await readJsonBody(req);
        const rawB64 = stripDataUrlPrefix(body.wavBase64);
        if (!rawB64) {
          return sendJson(res, 400, { ok: false, error: 'Thiếu dữ liệu âm thanh .WAV để phân tích phổ.' });
        }
        const wavBuf = Buffer.from(rawB64, 'base64');
        const spec = decodeWavToSpectrogram(wavBuf, {
          outCols: Number(body.outCols) || 200,
          outRows: Number(body.outRows) || 96,
          freqMin: Number(body.freqMin) || 300,
          freqMax: Number(body.freqMax) || 18000
        });
        return sendJson(res, 200, { ok: true, spectrogram: spec });
      }

      // ----------------------------------------------------------------------
      // 4. STUDIO 3: TRIPLE POLYGLOT FORGE (.PNG + .HTML + .ZIP)
      // ----------------------------------------------------------------------
      if (req.method === 'POST' && pathname === '/api/polyglot/forge') {
        const body = await readJsonBody(req);
        const customPngB64 = stripDataUrlPrefix(body.customPngBase64);
        const customPngBuffer = customPngB64 ? Buffer.from(customPngB64, 'base64') : null;

        const rawZipFiles = Array.isArray(body.zipFiles) ? body.zipFiles : [];
        const zipFiles = rawZipFiles.slice(0, 20).map((f, idx) => ({
          name: String(f.name || `secret-${idx + 1}.txt`),
          content: f.isBase64
            ? Buffer.from(stripDataUrlPrefix(f.content || ''), 'base64')
            : String(f.content ?? '')
        }));

        const forged = forgePolyglotFile({
          customPngBuffer,
          coverTheme: body.coverTheme || 'cyber-card',
          coverLabel: body.coverLabel || 'SPECTRAVEIL ARTIFACT',
          enableHtmlPersona: body.enableHtmlPersona !== false,
          enableZipPersona: body.enableZipPersona !== false,
          vaultTitle: body.vaultTitle || 'KÉT SẮT ĐA NHÂN CÁCH SPECTRAVEIL',
          secretNote: body.secretNote || 'Tài liệu mật được ngụy trang bên trong tệp ảnh PNG.',
          password: body.password || '',
          zipFiles
        });

        return sendJson(res, 200, {
          ok: true,
          filename: body.outputName || 'spectraveil-polyglot.png',
          fileBase64: forged.buffer.toString('base64'),
          anatomy: forged.anatomy
        });
      }

      // ----------------------------------------------------------------------
      // 5. STUDIO 4: PNG PIXEL LSB & UNIVERSAL BINARY X-RAY
      // ----------------------------------------------------------------------
      if (req.method === 'POST' && pathname === '/api/lsb/embed') {
        const body = await readJsonBody(req);
        if (!String(body.secretText ?? '').trim()) {
          return sendJson(res, 400, { ok: false, error: 'Vui lòng nhập nội dung cần giấu vào kênh LSB của ảnh.' });
        }
        const pngB64 = stripDataUrlPrefix(body.pngBase64);
        const pngBuffer = pngB64 ? Buffer.from(pngB64, 'base64') : null;

        const result = embedPngLsb({
          pngBuffer,
          secretText: body.secretText,
          password: body.password || ''
        });

        return sendJson(res, 200, {
          ok: true,
          pngBase64: result.pngBuffer.toString('base64'),
          stats: result.stats
        });
      }

      if (req.method === 'POST' && pathname === '/api/lsb/extract') {
        const body = await readJsonBody(req);
        const pngB64 = stripDataUrlPrefix(body.pngBase64);
        if (!pngB64) {
          return sendJson(res, 400, { ok: false, error: 'Vui lòng tải lên ảnh .PNG cần giải mã LSB.' });
        }
        const result = extractPngLsb({
          pngBuffer: Buffer.from(pngB64, 'base64'),
          password: body.password || ''
        });
        return sendJson(res, 200, { ok: true, ...result });
      }

      if (req.method === 'POST' && pathname === '/api/forensics/xray') {
        const body = await readJsonBody(req);
        const rawB64 = stripDataUrlPrefix(body.fileBase64);
        if (!rawB64) {
          return sendJson(res, 400, { ok: false, error: 'Thiếu dữ liệu tệp để chụp X-Quang nhị phân.' });
        }
        const buf = Buffer.from(rawB64, 'base64');
        const report = inspectBinaryAnatomy(buf, body.filename || 'artifact.bin', body.password || '');
        return sendJson(res, 200, { ok: true, report });
      }

      // ----------------------------------------------------------------------
      // 6. STATIC FRONTEND FILES
      // ----------------------------------------------------------------------
      if (req.method === 'GET' || req.method === 'HEAD') {
        const relPath = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
        const safePath = path.normalize(path.join(PUBLIC_DIR, relPath));

        if (!safePath.startsWith(PUBLIC_DIR)) {
          res.writeHead(403);
          res.end('Forbidden');
          return;
        }

        if (fs.existsSync(safePath) && fs.statSync(safePath).isFile()) {
          const ext = path.extname(safePath).toLowerCase();
          res.writeHead(200, {
            'Content-Type': MIME_TYPES[ext] || 'application/octet-stream',
            'Cache-Control': 'no-cache'
          });
          if (req.method === 'HEAD') {
            res.end();
          } else {
            fs.createReadStream(safePath).pipe(res);
          }
          return;
        }
      }

      sendJson(res, 404, { ok: false, error: `Không tìm thấy đường dẫn: ${pathname}` });
    } catch (err) {
      sendJson(res, 500, {
        ok: false,
        error: err && err.message ? err.message : 'Lỗi xử lý nội bộ trên máy chủ.'
      });
    }
  });
}

if (require.main === module) {
  const server = createAppServer();
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`\n🕵️‍♂️🔊 SpectraVeil Lab đang chạy tại: http://127.0.0.1:${PORT}`);
    console.log('   • Studio 1: Văn Bản Tàng Hình Zero-Width (VS-256) & Bẫy Rò Rỉ Canary');
    console.log('   • Studio 2: Vẽ Tranh / Mã QR Trong Sóng Âm (.WAV) & Máy Soi Phổ Thác Nước');
    console.log('   • Studio 3: Đúc File Đa Nhân Cách Triple Polyglot (.PNG + .HTML + .ZIP)');
    console.log('   • Studio 4: Giấu Tin Pixel LSB & Chụp X-Quang Giải Phẫu Nhị Phân\n');
  });
}

module.exports = { createAppServer };
