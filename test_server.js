/**
 * 🧪 Automated Verification Suite for SpectraVeil Lab (Port 4165)
 * Kiểm chứng thực tế cả 4 Trạm Giấu Tin ở cấp độ Byte, Mật mã & Phổ Tần Số FFT
 */

const assert = require('node:assert/strict');
const vm = require('node:vm');
const { createAppServer } = require('./server');

async function postJson(baseUrl, path, body) {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const json = await res.json();
  return { status: res.status, json };
}

async function runTests() {
  const server = createAppServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  console.log(`🔍 Đang chạy bộ kiểm thử SpectraVeil Lab trên cổng tạm :${port}...\n`);

  try {
    // 1. Health & Static UI Check
    {
      const res = await fetch(`${baseUrl}/api/health`);
      const data = await res.json();
      assert.equal(data.ok, true);
      assert.equal(data.modules.length, 5);

      const htmlRes = await fetch(`${baseUrl}/`);
      const html = await htmlRes.text();
      assert.ok(html.includes('SpectraVeil Lab'));
      console.log('✅ [1/6] Health API & Giao diện Frontend phục vụ chuẩn xác.');
    }

    // 2. Zero-Width VS-256 + AES-256-GCM + .trim() survival
    {
      const cover = 'Chiều nay uống cà phê nhé!';
      const secret = 'DB_PASS=SuperSecret#2026\nTOKEN=eyJhbGciOiJIUzI1NiJ9';

      const enc = await postJson(baseUrl, '/api/zerowidth/encode', {
        coverText: cover,
        secretText: secret,
        password: 'mật-khẩu-việt-4165',
        mode: 'vs256'
      });
      assert.equal(enc.status, 200);
      assert.equal(enc.json.stats.visibleChars, Array.from(cover).length);
      assert.equal(enc.json.stats.encrypted, true);

      // Simulate chat platform .trim()
      const trimmedChat = enc.json.stegoText.trim();

      // Wrong password must be rejected
      const wrongDec = await postJson(baseUrl, '/api/zerowidth/decode', {
        stegoText: trimmedChat,
        password: 'wrong-password'
      });
      assert.equal(wrongDec.json.decoded.valid, false);
      assert.equal(wrongDec.json.decoded.wrongPassword, true);

      // Right password unlocks exact secret & preserves visible text
      const okDec = await postJson(baseUrl, '/api/zerowidth/decode', {
        stegoText: trimmedChat,
        password: 'mật-khẩu-việt-4165'
      });
      assert.equal(okDec.json.decoded.valid, true);
      assert.equal(okDec.json.visibleText, cover);
      assert.equal(okDec.json.decoded.secretText, secret);
      console.log('✅ [2/6] Zero-Width VS-256 + Nén Deflate + Khóa AES-256-GCM sống sót qua .trim() & giải mã chuẩn 100%.');
    }

    // 3. Canary Leak Trap Attribution
    {
      const canaryRes = await postJson(baseUrl, '/api/zerowidth/canary', {
        coverText: 'Báo cáo tài chính nội bộ Q4 - Tuyệt mật.',
        recipients: ['Minh DevOps', 'Lan Kế Toán', 'Hùng Đối Tác'],
        secretNote: 'Cấm sao chép'
      });
      assert.equal(canaryRes.json.count, 3);

      // Visually stripped texts are 100% identical, raw strings are distinct
      assert.notEqual(canaryRes.json.items[0].stegoText, canaryRes.json.items[1].stegoText);

      // Suppose Lan leaks her copy:
      const leakScan = await postJson(baseUrl, '/api/zerowidth/decode', {
        stegoText: canaryRes.json.items[1].stegoText
      });
      assert.equal(leakScan.json.decoded.valid, true);
      assert.equal(leakScan.json.decoded.isCanary, true);
      assert.equal(leakScan.json.decoded.canary.recipient, 'Lan Kế Toán');
      console.log('✅ [3/6] Bẫy rò rỉ Canary tạo bản sao đồng nhất thị giác & bắt trúng tên kẻ làm lộ tin.');
    }

    // 4. Audio Spectrogram .WAV Synthesis + Radix-2 FFT Peak Verification
    {
      // Create a 32x64 grid where ONLY the top row (row 0 -> freqMax = 8000 Hz) is bright 255
      const rows = 32;
      const cols = 64;
      const grid = Array.from({ length: rows }, (_, r) =>
        Array.from({ length: cols }, () => (r === 2 ? 255 : 0))
      );

      const synth = await postJson(baseUrl, '/api/spectrogram/synthesize', {
        grid,
        durationSec: 1.5,
        freqMin: 1000,
        freqMax: 8000,
        cloakAmbience: false
      });
      assert.equal(synth.status, 200);
      const wavBuf = Buffer.from(synth.json.wavBase64, 'base64');
      assert.equal(wavBuf.toString('ascii', 0, 4), 'RIFF');
      assert.equal(wavBuf.toString('ascii', 8, 12), 'WAVE');

      const scan = await postJson(baseUrl, '/api/spectrogram/analyze', {
        wavBase64: synth.json.wavBase64,
        outCols: 32,
        outRows: 32,
        freqMin: 1000,
        freqMax: 8000
      });
      assert.equal(scan.status, 200);
      const specPixels = scan.json.spectrogram.pixels;

      // Verify row 2 (high frequency line) is dramatically brighter than row 20 (quiet low frequency region)
      const brightRowEnergy = specPixels[2][16];
      const darkRowEnergy = specPixels[20][16];
      assert.ok(brightRowEnergy > 200, `Expected bright frequency peak > 200, got ${brightRowEnergy}`);
      assert.ok(darkRowEnergy < 40, `Expected quiet background < 40, got ${darkRowEnergy}`);
      console.log(`✅ [4/6] Sóng âm .WAV Spectrogram tổng hợp & phục hồi chuẩn qua FFT (Peak=${brightRowEnergy}/255 vs Nền=${darkRowEnergy}/255).`);
    }

    // 5. Triple Polyglot (.PNG + Standalone Encrypted .HTML + Offset-Adjusted .ZIP)
    {
      const forge = await postJson(baseUrl, '/api/polyglot/forge', {
        coverTheme: 'finance-chart',
        enableHtmlPersona: true,
        enableZipPersona: true,
        vaultTitle: 'KÉT MẬT ALPHA',
        secretNote: 'Mật mã hạt nhân: OMEGA-4165',
        password: '4165',
        zipFiles: [
          { name: 'alpha-key.txt', content: 'SECRET_ZIP_CONTENT_999' },
          { name: 'sub/coords.json', content: '{"lat":10.77,"lng":106.70}' }
        ]
      });
      assert.equal(forge.status, 200);
      assert.deepEqual(forge.json.anatomy.personas, ['PNG', 'HTML', 'ZIP']);

      const polyBuf = Buffer.from(forge.json.fileBase64, 'base64');
      // Persona 1: Valid PNG signature
      assert.equal(polyBuf[0], 0x89);
      assert.equal(polyBuf.toString('ascii', 1, 4), 'PNG');

      // Persona 2: Test the actual standalone HTML decryption script inside a sandboxed VM (simulating file:// browser!)
      const htmlStr = polyBuf.toString('utf8');
      const scriptMatch = htmlStr.match(/<script>([\s\S]*?)<\/script>/);
      assert.ok(scriptMatch, 'Embedded HTML Vault script must exist');

      const domEls = {
        'sv-pass': { value: '4165' },
        'sv-err': { textContent: '', style: { display: 'none' } },
        'sv-lock-box': { style: { display: 'block' } },
        'sv-secret-view': { style: { display: 'none' } },
        'sv-secret-text': { textContent: '' }
      };
      const sandbox = {
        window: {},
        document: { getElementById: (id) => domEls[id] },
        TextEncoder,
        TextDecoder,
        Uint8Array,
        Uint32Array,
        DataView,
        atob: (b64) => Buffer.from(b64, 'base64').toString('binary'),
        Math,
        Array,
        JSON,
        parseInt
      };
      vm.runInNewContext(scriptMatch[1], sandbox);
      sandbox.window.__svUnlock();
      assert.equal(domEls['sv-secret-text'].textContent, 'Mật mã hạt nhân: OMEGA-4165');

      // Persona 3 + Binary X-Ray verification
      const xray = await postJson(baseUrl, '/api/forensics/xray', {
        fileBase64: forge.json.fileBase64,
        filename: 'spectraveil-polyglot.png'
      });
      assert.equal(xray.json.report.isPolyglot, true);
      assert.deepEqual(xray.json.report.personas, ['PNG', 'HTML', 'ZIP']);
      assert.equal(xray.json.report.zipInfo.entryCount, 2);
      assert.equal(xray.json.report.zipInfo.entries[0].crcValid, true);
      assert.equal(xray.json.report.zipInfo.entries[0].textPreview, 'SECRET_ZIP_CONTENT_999');
      console.log('✅ [5/6] File Đa Nhân Cách Triple Polyglot hợp lệ đồng thời ở cả 3 hình thái (.PNG + .HTML Vault 256-bit + .ZIP Offset).');
    }

    // 6. PNG Pixel LSB Embed + PSNR + Extract
    {
      const lsbEmbed = await postJson(baseUrl, '/api/lsb/embed', {
        secretText: 'Tin mật giấu trong lớp hạt điểm ảnh Bit-0!',
        password: 'lsb-key-99'
      });
      assert.equal(lsbEmbed.status, 200);
      assert.ok(lsbEmbed.json.stats.psnrDb > 50, `Expected PSNR > 50 dB, got ${lsbEmbed.json.stats.psnrDb}`);

      const lsbExt = await postJson(baseUrl, '/api/lsb/extract', {
        pngBase64: lsbEmbed.json.pngBase64,
        password: 'lsb-key-99'
      });
      assert.equal(lsbExt.json.found, true);
      assert.equal(lsbExt.json.secretText, 'Tin mật giấu trong lớp hạt điểm ảnh Bit-0!');
      console.log(`✅ [6/6] Giấu tin PNG Pixel LSB khóa AES-256-GCM đạt PSNR = ${lsbEmbed.json.stats.psnrDb} dB & trích xuất chuẩn xác.`);
    }

    console.log('\n🎉 TẤT CẢ 6/6 BÀI KIỂM ĐỊNH KỸ THUẬT ĐỀU VƯỢT QUA XUẤT SẮC!');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

runTests().catch((err) => {
  console.error('❌ Kiểm thử thất bại:', err);
  process.exit(1);
});
