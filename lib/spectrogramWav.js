/**
 * 🔊 Audio Spectrogram Synthesizer & Radix-2 FFT Decoder (16-bit PCM .WAV)
 * - Biến hình ảnh 2D / chữ mật / mã ma trận / nét vẽ thành sóng âm .WAV thực thụ
 * - Sử dụng bộ tạo dao động Phasor liên tục pha (Continuous-Phase Oscillator Bank) -> 0 tiếng click rác
 * - Hỗ trợ chế độ "Sci-Fi Wind Cloak" (trộn lớp nhiễu hồng vũ trụ nhẹ để ngụy trang tai nghe)
 * - Kèm bộ giải mã phổ tần số FFT Cooley-Tukey + cửa sổ Hann để kiểm định & quét nhanh file .WAV
 */

const SAMPLE_RATE = 44100;

// Compact 5x7 Bitmap Font for Server-Side Text Rendering
const FONT_5X7 = {
  A: ['01110', '10001', '10001', '11111', '10001', '10001', '10001'],
  B: ['11110', '10001', '10001', '11110', '10001', '10001', '11110'],
  C: ['01111', '10000', '10000', '10000', '10000', '10000', '01111'],
  D: ['11110', '10001', '10001', '10001', '10001', '10001', '11110'],
  E: ['11111', '10000', '10000', '11110', '10000', '10000', '11111'],
  F: ['11111', '10000', '10000', '11110', '10000', '10000', '10000'],
  G: ['01111', '10000', '10000', '10111', '10001', '10001', '01111'],
  H: ['10001', '10001', '10001', '11111', '10001', '10001', '10001'],
  I: ['11111', '00100', '00100', '00100', '00100', '00100', '11111'],
  J: ['00111', '00010', '00010', '00010', '10010', '10010', '01100'],
  K: ['10001', '10010', '10100', '11000', '10100', '10010', '10001'],
  L: ['10000', '10000', '10000', '10000', '10000', '10000', '11111'],
  M: ['10001', '11011', '10101', '10101', '10001', '10001', '10001'],
  N: ['10001', '11001', '10101', '10011', '10001', '10001', '10001'],
  O: ['01110', '10001', '10001', '10001', '10001', '10001', '01110'],
  P: ['11110', '10001', '10001', '11110', '10000', '10000', '10000'],
  Q: ['01110', '10001', '10001', '10001', '10101', '10010', '01101'],
  R: ['11110', '10001', '10001', '11110', '10100', '10010', '10001'],
  S: ['01111', '10000', '10000', '01110', '00001', '00001', '11110'],
  T: ['11111', '00100', '00100', '00100', '00100', '00100', '00100'],
  U: ['10001', '10001', '10001', '10001', '10001', '10001', '01110'],
  V: ['10001', '10001', '10001', '10001', '10001', '01010', '00100'],
  W: ['10001', '10001', '10001', '10101', '10101', '11011', '10001'],
  X: ['10001', '10001', '01010', '00100', '01010', '10001', '10001'],
  Y: ['10001', '10001', '01010', '00100', '00100', '00100', '00100'],
  Z: ['11111', '00001', '00010', '00100', '01000', '10000', '11111'],
  '0': ['01110', '10001', '10011', '10101', '11001', '10001', '01110'],
  '1': ['00100', '01100', '00100', '00100', '00100', '00100', '01110'],
  '2': ['01110', '10001', '00001', '00110', '01000', '10000', '11111'],
  '3': ['11110', '00001', '00001', '01110', '00001', '00001', '11110'],
  '4': ['10010', '10010', '10010', '11111', '00010', '00010', '00010'],
  '5': ['11111', '10000', '10000', '11110', '00001', '00001', '11110'],
  '6': ['01111', '10000', '10000', '11110', '10001', '10001', '01110'],
  '7': ['11111', '00001', '00010', '00100', '01000', '01000', '01000'],
  '8': ['01110', '10001', '10001', '01110', '10001', '10001', '01110'],
  '9': ['01110', '10001', '10001', '01111', '00001', '00001', '11110'],
  ':': ['00000', '00100', '00100', '00000', '00100', '00100', '00000'],
  '-': ['00000', '00000', '00000', '11111', '00000', '00000', '00000'],
  '!': ['00100', '00100', '00100', '00100', '00100', '00000', '00100'],
  '?': ['01110', '10001', '00010', '00100', '00100', '00000', '00100'],
  '#': ['01010', '11111', '01010', '01010', '11111', '01010', '00000'],
  '.': ['00000', '00000', '00000', '00000', '00000', '00110', '00110'],
  '/': ['00001', '00010', '00010', '00100', '01000', '01000', '10000'],
  ' ': ['00000', '00000', '00000', '00000', '00000', '00000', '00000']
};

function normalizeAsciiText(input) {
  return String(input || 'SOS 4165')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/đ/gi, 'D')
    .toUpperCase();
}

function createEmptyGrid(width, height) {
  return Array.from({ length: height }, () => new Uint8Array(width));
}

function drawPixelTextOnGrid(grid, text, startX, startY, scale = 3, brightness = 255) {
  const clean = normalizeAsciiText(text);
  const height = grid.length;
  const width = grid[0].length;
  let cursorX = startX;

  for (const ch of clean) {
    const glyph = FONT_5X7[ch] || FONT_5X7[' '];
    for (let gy = 0; gy < 7; gy++) {
      for (let gx = 0; gx < 5; gx++) {
        if (glyph[gy][gx] === '1') {
          for (let sy = 0; sy < scale; sy++) {
            for (let sx = 0; sx < scale; sx++) {
              const py = startY + gy * scale + sy;
              const px = cursorX + gx * scale + sx;
              if (py >= 0 && py < height && px >= 0 && px < width) {
                grid[py][px] = brightness;
              }
            }
          }
        }
      }
    }
    cursorX += 6 * scale;
  }
}

/**
 * Generate built-in graphical spectrogram presets
 */
function buildPresetGrid(presetId = 'cyber-eye', customText = 'CODE: 4165', width = 180, height = 72) {
  const grid = createEmptyGrid(width, height);

  if (presetId === 'qr-beacon') {
    // Draw a crisp QR-like finder beacon + binary payload + label
    const size = 42;
    const ox = 14;
    const oy = Math.floor((height - size) / 2);

    const drawFinder = (fx, fy) => {
      for (let y = 0; y < 11; y++) {
        for (let x = 0; x < 11; x++) {
          const border = x === 0 || x === 10 || y === 0 || y === 10;
          const core = x >= 3 && x <= 7 && y >= 3 && y <= 7;
          if (border || core) {
            if (fy + y < height && fx + x < width) grid[fy + y][fx + x] = 255;
          }
        }
      }
    };
    drawFinder(ox, oy);
    drawFinder(ox + size - 11, oy);
    drawFinder(ox, oy + size - 11);

    // Deterministic data modules from customText
    let seed = 0x9e3779b9;
    for (let i = 0; i < customText.length; i++) {
      seed = ((seed << 5) - seed + customText.charCodeAt(i)) >>> 0;
    }
    for (let y = 13; y < size - 2; y += 3) {
      for (let x = 13; x < size - 2; x += 3) {
        seed = (seed * 1664525 + 1013904223) >>> 0;
        if ((seed >>> 24) & 1) {
          for (let dy = 0; dy < 2; dy++) {
            for (let dx = 0; dx < 2; dx++) {
              if (oy + y + dy < height && ox + x + dx < width) {
                grid[oy + y + dy][ox + x + dx] = 235;
              }
            }
          }
        }
      }
    }

    drawPixelTextOnGrid(grid, customText || 'VAULT 4165', ox + size + 12, Math.floor(height / 2) - 10, 3, 255);
    return grid;
  }

  if (presetId === 'cyber-eye') {
    // All-Seeing Cyber Eye + Frame + Secret Tag
    const cx = 42;
    const cy = Math.floor(height / 2);
    for (let x = 8; x <= 76; x++) {
      const norm = (x - cx) / 34;
      const arch = Math.round(18 * (1 - norm * norm));
      if (cy - arch >= 0 && cy - arch < height) grid[cy - arch][x] = 255;
      if (cy + arch >= 0 && cy + arch < height) grid[cy + arch][x] = 255;
    }
    for (let y = 0; y < height; y++) {
      for (let x = 8; x <= 76; x++) {
        const d = Math.hypot(x - cx, y - cy);
        if (Math.abs(d - 11) < 1.6 || d < 4.2) {
          grid[y][x] = 255;
        }
      }
    }
    drawPixelTextOnGrid(grid, customText || 'EYE-4165', 86, Math.floor(height / 2) - 10, 2, 255);
    return grid;
  }

  // Default: Framed Banner with bold Pixel Text
  for (let x = 4; x < width - 4; x++) {
    grid[3][x] = 190;
    grid[height - 4][x] = 190;
  }
  const clean = normalizeAsciiText(customText || 'SECRET 4165');
  const scale = clean.length <= 8 ? 3 : 2;
  const textW = clean.length * 6 * scale;
  const sx = Math.max(6, Math.floor((width - textW) / 2));
  const sy = Math.max(8, Math.floor((height - 7 * scale) / 2));
  drawPixelTextOnGrid(grid, clean, sx, sy, scale, 255);
  return grid;
}

/**
 * Synthesize 16-bit Mono PCM WAV Buffer from 2D Pixel Grid
 * grid[row][col]: row 0 = highest frequency (freqMax), row H-1 = lowest frequency (freqMin)
 */
function synthesizeSpectrogramWav({
  grid,
  durationSec = 4.0,
  freqMin = 800,
  freqMax = 9200,
  cloakAmbience = false,
  sampleRate = SAMPLE_RATE
}) {
  const height = grid.length;
  const width = grid[0]?.length || 1;

  const clampedDuration = Math.min(12, Math.max(1.0, Number(durationSec) || 4.0));
  const fLow = Math.max(200, Math.min(19000, Number(freqMin) || 800));
  const fHigh = Math.max(fLow + 400, Math.min(20500, Number(freqMax) || 9200));

  const totalSamples = Math.floor(clampedDuration * sampleRate);
  const floatPcm = new Float32Array(totalSamples);

  // Deterministic PRNG for randomizing initial phases so oscillators don't peak-align
  let seed = 0x13579bdf;
  const nextRand = () => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 0x100000000;
  };

  // Precompute oscillator frequencies & unit-circle rotation steps
  const cosStep = new Float64Array(height);
  const sinStep = new Float64Array(height);
  const oscRe = new Float64Array(height);
  const oscIm = new Float64Array(height);

  for (let r = 0; r < height; r++) {
    const ratio = height > 1 ? r / (height - 1) : 0;
    const freq = fHigh - ratio * (fHigh - fLow);
    const omega = (2 * Math.PI * freq) / sampleRate;
    cosStep[r] = Math.cos(omega);
    sinStep[r] = Math.sin(omega);
    const phi0 = nextRand() * 2 * Math.PI;
    oscRe[r] = Math.cos(phi0);
    oscIm[r] = Math.sin(phi0);
  }

  const samplesPerCol = totalSamples / width;

  for (let col = 0; col < width; col++) {
    const sStart = Math.floor(col * samplesPerCol);
    const sEnd = col === width - 1 ? totalSamples : Math.floor((col + 1) * samplesPerCol);
    const segLen = Math.max(1, sEnd - sStart);
    const nextCol = Math.min(width - 1, col + 1);

    for (let r = 0; r < height; r++) {
      // Gamma curve (^1.5) gives crisp dark background & vivid bright strokes on spectrograms
      const v0 = (grid[r][col] || 0) / 255;
      const v1 = (grid[r][nextCol] || 0) / 255;

      if (v0 < 0.015 && v1 < 0.015) {
        // Advance oscillator phase analytically for this segment without inner loop!
        const ratio = height > 1 ? r / (height - 1) : 0;
        const freq = fHigh - ratio * (fHigh - fLow);
        const deltaPhi = (2 * Math.PI * freq * segLen) / sampleRate;
        const cD = Math.cos(deltaPhi);
        const sD = Math.sin(deltaPhi);
        const re = oscRe[r];
        const im = oscIm[r];
        oscRe[r] = re * cD - im * sD;
        oscIm[r] = re * sD + im * cD;
        continue;
      }

      const a0 = Math.pow(v0, 1.45);
      const a1 = Math.pow(v1, 1.45);
      const dA = (a1 - a0) / segLen;
      let amp = a0;

      let re = oscRe[r];
      let im = oscIm[r];
      const cS = cosStep[r];
      const sS = sinStep[r];

      for (let s = sStart; s < sEnd; s++) {
        floatPcm[s] += im * amp;
        amp += dA;
        const nextRe = re * cS - im * sS;
        im = re * sS + im * cS;
        re = nextRe;
      }

      // Renormalize phasor slightly per column to eliminate floating-point drift
      const mag = Math.hypot(re, im) || 1;
      oscRe[r] = re / mag;
      oscIm[r] = im / mag;
    }
  }

  // Normalize signal peak
  let peak = 1e-6;
  for (let i = 0; i < totalSamples; i++) {
    const abs = Math.abs(floatPcm[i]);
    if (abs > peak) peak = abs;
  }

  const targetGain = (cloakAmbience ? 0.80 : 0.88) / peak;

  // Optional Sci-Fi Deep Space Pink-Drone Cloak (Paul Kellet pink noise filter + low sub-hum)
  let b0 = 0, b1 = 0, b2 = 0;
  const fadeSamples = Math.min(Math.floor(sampleRate * 0.04), Math.floor(totalSamples / 8));

  const wavByteLen = 44 + totalSamples * 2;
  const wavBuf = Buffer.alloc(wavByteLen);

  // Write RIFF WAVE PCM Header
  wavBuf.write('RIFF', 0);
  wavBuf.writeUInt32LE(wavByteLen - 8, 4);
  wavBuf.write('WAVE', 8);
  wavBuf.write('fmt ', 12);
  wavBuf.writeUInt32LE(16, 16);            // PCM chunk size
  wavBuf.writeUInt16LE(1, 20);             // AudioFormat = 1 (PCM)
  wavBuf.writeUInt16LE(1, 22);             // NumChannels = 1 (Mono)
  wavBuf.writeUInt32LE(sampleRate, 24);    // SampleRate
  wavBuf.writeUInt32LE(sampleRate * 2, 28);// ByteRate
  wavBuf.writeUInt16LE(2, 32);             // BlockAlign
  wavBuf.writeUInt16LE(16, 34);            // BitsPerSample = 16
  wavBuf.write('data', 36);
  wavBuf.writeUInt32LE(totalSamples * 2, 40);

  for (let i = 0; i < totalSamples; i++) {
    let val = floatPcm[i] * targetGain;

    if (cloakAmbience) {
      const white = nextRand() * 2 - 1;
      b0 = 0.99765 * b0 + white * 0.0990460;
      b1 = 0.96300 * b1 + white * 0.2965164;
      b2 = 0.57000 * b2 + white * 1.0526913;
      const pink = (b0 + b1 + b2 + white * 0.1848) * 0.012;
      const subDrone = Math.sin((2 * Math.PI * 110 * i) / sampleRate) * 0.045;
      val += pink + subDrone;
    }

    // Smooth edge envelope
    if (i < fadeSamples) {
      val *= i / fadeSamples;
    } else if (i > totalSamples - fadeSamples) {
      val *= (totalSamples - i) / fadeSamples;
    }

    const clamped = Math.max(-1, Math.min(1, val));
    wavBuf.writeInt16LE(Math.round(clamped * 32767), 44 + i * 2);
  }

  return {
    wavBuffer: wavBuf,
    meta: {
      sampleRate,
      durationSec: Number((totalSamples / sampleRate).toFixed(2)),
      totalSamples,
      byteLength: wavByteLen,
      freqMin: fLow,
      freqMax: fHigh,
      gridWidth: width,
      gridHeight: height,
      cloakAmbience: Boolean(cloakAmbience)
    }
  };
}

/**
 * In-place Radix-2 Cooley-Tukey FFT
 */
function fftRadix2(re, im) {
  const n = re.length;
  let j = 0;
  for (let i = 0; i < n; i++) {
    if (i < j) {
      const tr = re[i]; re[i] = re[j]; re[j] = tr;
      const ti = im[i]; im[i] = im[j]; im[j] = ti;
    }
    let m = n >> 1;
    while (m >= 1 && j >= m) {
      j -= m;
      m >>= 1;
    }
    j += m;
  }

  for (let len = 2; len <= n; len <<= 1) {
    const half = len >> 1;
    const ang = (-2 * Math.PI) / len;
    const wStepRe = Math.cos(ang);
    const wStepIm = Math.sin(ang);

    for (let i = 0; i < n; i += len) {
      let wRe = 1;
      let wIm = 0;
      for (let k = 0; k < half; k++) {
        const uRe = re[i + k];
        const uIm = im[i + k];
        const vRe = re[i + k + half] * wRe - im[i + k + half] * wIm;
        const vIm = re[i + k + half] * wIm + im[i + k + half] * wRe;

        re[i + k] = uRe + vRe;
        im[i + k] = uIm + vIm;
        re[i + k + half] = uRe - vRe;
        im[i + k + half] = uIm - vIm;

        const nextWRe = wRe * wStepRe - wIm * wStepIm;
        wIm = wRe * wStepIm + wIm * wStepRe;
        wRe = nextWRe;
      }
    }
  }
}

/**
 * Parse PCM WAV Buffer & Compute High-Resolution Spectrogram Grid via FFT
 */
function decodeWavToSpectrogram(wavBuffer, {
  outCols = 180,
  outRows = 96,
  freqMin = 300,
  freqMax = 18000,
  fftSize = 2048
} = {}) {
  if (!wavBuffer || wavBuffer.length < 44 || wavBuffer.toString('ascii', 0, 4) !== 'RIFF') {
    throw new Error('File không phải định dạng chuẩn RIFF WAVE (.wav).');
  }

  // Locate fmt and data chunks dynamically (handles extra LIST/JUNK chunks)
  let offset = 12;
  let audioFormat = 1;
  let channels = 1;
  let sampleRate = 44100;
  let bitsPerSample = 16;
  let dataStart = -1;
  let dataLen = 0;

  while (offset + 8 <= wavBuffer.length) {
    const chunkId = wavBuffer.toString('ascii', offset, offset + 4);
    const chunkSize = wavBuffer.readUInt32LE(offset + 4);
    if (chunkId === 'fmt ' && offset + 8 + 16 <= wavBuffer.length) {
      audioFormat = wavBuffer.readUInt16LE(offset + 8);
      channels = wavBuffer.readUInt16LE(offset + 10);
      sampleRate = wavBuffer.readUInt32LE(offset + 12);
      bitsPerSample = wavBuffer.readUInt16LE(offset + 22);
    } else if (chunkId === 'data') {
      dataStart = offset + 8;
      dataLen = Math.min(chunkSize, wavBuffer.length - dataStart);
      break;
    }
    offset += 8 + chunkSize + (chunkSize & 1);
  }

  if (dataStart < 0 || dataLen <= 0) {
    throw new Error('Không tìm thấy vùng dữ liệu âm thanh PCM trong file .WAV.');
  }

  const bytesPerSample = Math.max(1, Math.floor(bitsPerSample / 8));
  const frameSize = bytesPerSample * channels;
  const totalFrames = Math.floor(dataLen / frameSize);
  const samples = new Float32Array(totalFrames);

  for (let i = 0; i < totalFrames; i++) {
    const pos = dataStart + i * frameSize;
    if (audioFormat === 3 && bitsPerSample === 32) {
      samples[i] = wavBuffer.readFloatLE(pos);
    } else if (bitsPerSample === 16) {
      samples[i] = wavBuffer.readInt16LE(pos) / 32768;
    } else if (bitsPerSample === 8) {
      samples[i] = (wavBuffer.readUInt8(pos) - 128) / 128;
    } else if (bitsPerSample === 24) {
      const b0 = wavBuffer[pos];
      const b1 = wavBuffer[pos + 1];
      const b2 = wavBuffer[pos + 2];
      const v = (b2 << 16) | (b1 << 8) | b0;
      samples[i] = (v & 0x800000 ? v | ~0xffffff : v) / 8388608;
    }
  }

  const N = fftSize;
  const hann = new Float64Array(N);
  for (let i = 0; i < N; i++) {
    hann[i] = 0.5 * (1 - Math.cos((2 * Math.PI * i) / (N - 1)));
  }

  const nyquist = sampleRate / 2;
  const effMax = Math.min(nyquist, Math.max(freqMin + 200, freqMax));
  const effMin = Math.max(50, Math.min(effMax - 100, freqMin));

  const cols = Math.min(400, Math.max(32, outCols));
  const rows = Math.min(200, Math.max(32, outRows));
  const dbMatrix = Array.from({ length: rows }, () => new Float32Array(cols));

  let maxDb = -120;
  const re = new Float64Array(N);
  const im = new Float64Array(N);

  for (let c = 0; c < cols; c++) {
    const center = Math.floor(((c + 0.5) / cols) * totalFrames);
    const start = center - (N >> 1);

    for (let i = 0; i < N; i++) {
      const idx = start + i;
      const s = idx >= 0 && idx < totalFrames ? samples[idx] : 0;
      re[i] = s * hann[i];
      im[i] = 0;
    }

    fftRadix2(re, im);

    for (let r = 0; r < rows; r++) {
      const ratio = rows > 1 ? r / (rows - 1) : 0;
      const freq = effMax - ratio * (effMax - effMin);
      const binFloat = (freq / sampleRate) * N;
      const b0 = Math.max(1, Math.min((N >> 1) - 2, Math.floor(binFloat)));
      const frac = binFloat - b0;

      const mag0 = Math.hypot(re[b0], im[b0]);
      const mag1 = Math.hypot(re[b0 + 1], im[b0 + 1]);
      const mag = mag0 + (mag1 - mag0) * frac;
      const db = 20 * Math.log10(mag / (N * 0.25) + 1e-9);
      dbMatrix[r][c] = db;
      if (db > maxDb) maxDb = db;
    }
  }

  // Normalize dynamic range (48 dB window below peak) to 0..255
  const dynamicRangeDb = 48;
  const minDb = maxDb - dynamicRangeDb;
  const pixels = Array.from({ length: rows }, (_, r) => {
    const rowArr = new Array(cols);
    for (let c = 0; c < cols; c++) {
      const norm = (dbMatrix[r][c] - minDb) / dynamicRangeDb;
      rowArr[c] = Math.max(0, Math.min(255, Math.round(norm * 255)));
    }
    return rowArr;
  });

  return {
    sampleRate,
    channels,
    bitsPerSample,
    durationSec: Number((totalFrames / sampleRate).toFixed(2)),
    freqMin: effMin,
    freqMax: Math.round(effMax),
    cols,
    rows,
    pixels
  };
}

module.exports = {
  SAMPLE_RATE,
  buildPresetGrid,
  synthesizeSpectrogramWav,
  decodeWavToSpectrogram
};
