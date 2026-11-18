/**
 * 🕵️‍♂️ Zero-Width & Variation Selector Steganography Engine
 * - Mode 'vs256': Unicode Variation Selectors (U+FE00..U+FE0F & U+E0100..U+E01EF) -> 1 full byte / codepoint!
 * - Mode 'zw4'  : Standard BMP Zero-Width (U+200B, U+200C, U+200D, U+2060) -> 2 bits / codepoint
 * - Deflate compression + Optional AES-256-GCM (Scrypt) + Canary Leak Trap Attribution
 */

const crypto = require('node:crypto');
const zlib = require('node:zlib');

const MAGIC_0 = 0x53; // 'S'
const MAGIC_1 = 0x56; // 'V'

const FLAG_COMPRESSED = 0x01;
const FLAG_ENCRYPTED = 0x02;
const FLAG_CANARY = 0x04;

// BMP 4-ary Zero-Width Alphabet
const ZW4_CHARS = [
  0x200b, // Zero Width Space (00)
  0x200c, // Zero Width Non-Joiner (01)
  0x200d, // Zero Width Joiner (10)
  0x2060  // Word Joiner (11)
];

const ZW4_MAP = new Map([
  [0x200b, 0],
  [0x200c, 1],
  [0x200d, 2],
  [0x2060, 3]
]);

// Known invisible / zero-width codepoints for forensic microscope
const INVISIBLE_NAMES = new Map([
  [0x200b, 'ZWSP (U+200B)'],
  [0x200c, 'ZWNJ (U+200C)'],
  [0x200d, 'ZWJ (U+200D)'],
  [0x2060, 'WJ (U+2060)'],
  [0xfeff, 'BOM/ZWNBSP (U+FEFF)'],
  [0x200e, 'LRM (U+200E)'],
  [0x200f, 'RLM (U+200F)'],
  [0x034f, 'CGJ (U+034F)']
]);

// IEEE 802.3 CRC32
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function byteToVS256CodePoint(byte) {
  const b = byte & 0xff;
  return b < 16 ? (0xfe00 + b) : (0xe0100 + (b - 16));
}

function vs256CodePointToByte(cp) {
  if (cp >= 0xfe00 && cp <= 0xfe0f) return cp - 0xfe00;
  if (cp >= 0xe0100 && cp <= 0xe01ef) return (cp - 0xe0100) + 16;
  return -1;
}

function isInvisibleStegoCodePoint(cp) {
  return vs256CodePointToByte(cp) !== -1 || ZW4_MAP.has(cp) || INVISIBLE_NAMES.has(cp);
}

function describeCodePoint(cp) {
  const vsByte = vs256CodePointToByte(cp);
  if (vsByte !== -1) {
    return `VS-${vsByte + 1} (U+${cp.toString(16).toUpperCase()} → 0x${vsByte.toString(16).padStart(2, '0').toUpperCase()})`;
  }
  if (INVISIBLE_NAMES.has(cp)) {
    return INVISIBLE_NAMES.get(cp);
  }
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

function bytesToInvisibleString(buf, mode = 'vs256') {
  const cps = [];
  if (mode === 'zw4') {
    for (let i = 0; i < buf.length; i++) {
      const b = buf[i];
      cps.push(
        ZW4_CHARS[(b >> 6) & 0x03],
        ZW4_CHARS[(b >> 4) & 0x03],
        ZW4_CHARS[(b >> 2) & 0x03],
        ZW4_CHARS[b & 0x03]
      );
    }
  } else {
    for (let i = 0; i < buf.length; i++) {
      cps.push(byteToVS256CodePoint(buf[i]));
    }
  }
  // Chunk fromCodePoint calls to avoid argument stack limits on large payloads
  let out = '';
  const CHUNK = 2048;
  for (let i = 0; i < cps.length; i += CHUNK) {
    out += String.fromCodePoint(...cps.slice(i, i + CHUNK));
  }
  return out;
}

function deriveKey(password, salt) {
  return crypto.scryptSync(String(password), salt, 32, { N: 16384, r: 8, p: 1 });
}

function packEnvelope({ secretText, password = '', canaryMeta = null }) {
  let flags = 0;
  let bodyObj = String(secretText ?? '');

  if (canaryMeta) {
    flags |= FLAG_CANARY;
    bodyObj = JSON.stringify({
      canary: canaryMeta,
      note: String(secretText ?? '')
    });
  }

  const rawBytes = Buffer.from(bodyObj, 'utf8');
  const compressed = zlib.deflateRawSync(rawBytes, { level: 9 });

  let payloadBytes = rawBytes;
  if (compressed.length + 2 < rawBytes.length) {
    flags |= FLAG_COMPRESSED;
    payloadBytes = compressed;
  }

  const cleanPass = String(password || '');
  if (cleanPass.length > 0) {
    flags |= FLAG_ENCRYPTED;
    const salt = crypto.randomBytes(8);
    const iv = crypto.randomBytes(12);
    const key = deriveKey(cleanPass, salt);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(payloadBytes), cipher.final()]);
    const tag = cipher.getAuthTag(); // 16 bytes

    // Header: [S, V, flags, salt(8), iv(12), tag(16), ciphertext...]
    return {
      envelope: Buffer.concat([Buffer.from([MAGIC_0, MAGIC_1, flags]), salt, iv, tag, encrypted]),
      rawLength: rawBytes.length,
      packedLength: payloadBytes.length,
      compressed: Boolean(flags & FLAG_COMPRESSED),
      encrypted: true
    };
  }

  // Unencrypted Header: [S, V, flags, crc32(4), payload...]
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(payloadBytes), 0);
  return {
    envelope: Buffer.concat([Buffer.from([MAGIC_0, MAGIC_1, flags]), crcBuf, payloadBytes]),
    rawLength: rawBytes.length,
    packedLength: payloadBytes.length,
    compressed: Boolean(flags & FLAG_COMPRESSED),
    encrypted: false
  };
}

function unpackEnvelope(buf, password = '') {
  if (!buf || buf.length < 7) {
    return { valid: false, error: 'Không tìm thấy gói dữ liệu tàng hình hợp lệ.' };
  }
  if (buf[0] !== MAGIC_0 || buf[1] !== MAGIC_1) {
    return { valid: false, error: 'Phát hiện ký tự tàng hình lạ (không mang chữ ký SpectraVeil SV).' };
  }

  const flags = buf[2];
  const isCompressed = Boolean(flags & FLAG_COMPRESSED);
  const isEncrypted = Boolean(flags & FLAG_ENCRYPTED);
  const isCanary = Boolean(flags & FLAG_CANARY);

  let payloadBytes;

  if (isEncrypted) {
    if (buf.length < 3 + 8 + 12 + 16) {
      return { valid: false, error: 'Gói tin mã hóa bị cắt cụt hoặc hỏng cấu trúc.' };
    }
    const cleanPass = String(password || '');
    if (!cleanPass) {
      return {
        valid: false,
        requiresPassword: true,
        encrypted: true,
        compressed: isCompressed,
        isCanary,
        error: 'Tin mật này đã được khóa bằng AES-256-GCM. Vui lòng nhập mật khẩu để mở khóa.'
      };
    }
    const salt = buf.subarray(3, 11);
    const iv = buf.subarray(11, 23);
    const tag = buf.subarray(23, 39);
    const ciphertext = buf.subarray(39);

    try {
      const key = deriveKey(cleanPass, salt);
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);
      payloadBytes = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      return {
        valid: false,
        requiresPassword: true,
        wrongPassword: true,
        encrypted: true,
        compressed: isCompressed,
        isCanary,
        error: 'Sai mật khẩu giải mã AES-256-GCM hoặc chuỗi văn bản đã bị cắt bớt!'
      };
    }
  } else {
    const expectedCrc = buf.readUInt32BE(3);
    payloadBytes = buf.subarray(7);
    const actualCrc = crc32(payloadBytes);
    if (expectedCrc !== actualCrc) {
      return {
        valid: false,
        error: `Lỗi toàn vẹn CRC-32 (Expected 0x${expectedCrc.toString(16)}, Got 0x${actualCrc.toString(16)}). Chuỗi có thể đã bị cắt mất một phần.`
      };
    }
  }

  let decodedBytes = payloadBytes;
  if (isCompressed) {
    try {
      decodedBytes = zlib.inflateRawSync(payloadBytes);
    } catch {
      return { valid: false, error: 'Giải nén Deflate thất bại trên gói dữ liệu ẩn.' };
    }
  }

  const text = decodedBytes.toString('utf8');
  if (isCanary) {
    try {
      const parsed = JSON.parse(text);
      return {
        valid: true,
        encrypted: isEncrypted,
        compressed: isCompressed,
        isCanary: true,
        canary: parsed.canary || null,
        secretText: parsed.note || ''
      };
    } catch {
      // Fallback to plain text
    }
  }

  return {
    valid: true,
    encrypted: isEncrypted,
    compressed: isCompressed,
    isCanary: false,
    canary: null,
    secretText: text
  };
}

/**
 * Strip existing stego characters from cover text before embedding a fresh payload
 */
function stripInvisibleStego(text) {
  let clean = '';
  for (const ch of String(text || '')) {
    const cp = ch.codePointAt(0);
    if (!isInvisibleStegoCodePoint(cp)) {
      clean += ch;
    }
  }
  return clean;
}

/**
 * Split cover text right after the first visible character so chat apps' .trim() never touches the payload
 */
function injectIntoCover(cleanCover, invisiblePayload) {
  const chars = Array.from(cleanCover);
  if (chars.length === 0) {
    return `Tin nhắn${invisiblePayload}!`;
  }
  if (chars.length === 1) {
    return chars[0] + invisiblePayload;
  }
  // Inject right after first non-space character so start/end trim is 100% safe
  let insertIdx = 1;
  for (let i = 0; i < chars.length - 1; i++) {
    if (chars[i].trim().length > 0) {
      insertIdx = i + 1;
      break;
    }
  }
  return chars.slice(0, insertIdx).join('') + invisiblePayload + chars.slice(insertIdx).join('');
}

function encodeZeroWidth({
  coverText = 'Chiều nay uống cà phê nhé!',
  secretText = '',
  password = '',
  mode = 'vs256',
  canaryMeta = null
}) {
  const cleanCover = stripInvisibleStego(coverText || 'Chiều nay uống cà phê nhé!');
  const normalizedMode = mode === 'zw4' ? 'zw4' : 'vs256';

  const packed = packEnvelope({ secretText, password, canaryMeta });
  const invisibleStr = bytesToInvisibleString(packed.envelope, normalizedMode);
  const stegoText = injectIntoCover(cleanCover, invisibleStr);

  const visibleCodePoints = Array.from(cleanCover).length;
  const totalCodePoints = Array.from(stegoText).length;
  const invisibleCodePoints = totalCodePoints - visibleCodePoints;

  return {
    stegoText,
    cleanCover,
    mode: normalizedMode,
    stats: {
      visibleChars: visibleCodePoints,
      totalCodePoints,
      invisibleCodePoints,
      utf16Length: stegoText.length,
      secretByteLength: packed.rawLength,
      envelopeByteLength: packed.envelope.length,
      compressed: packed.compressed,
      encrypted: packed.encrypted,
      densityBitsPerChar: normalizedMode === 'vs256' ? 8 : 2
    }
  };
}

function inspectAndDecodeZeroWidth({ stegoText = '', password = '' }) {
  const str = String(stegoText || '');
  const vsBytes = [];
  const zwQuats = [];
  const microscope = [];
  let visibleChars = '';
  let invisibleCount = 0;
  let totalCodePoints = 0;

  for (const ch of str) {
    const cp = ch.codePointAt(0);
    const vsB = vs256CodePointToByte(cp);
    const zwQ = ZW4_MAP.has(cp) ? ZW4_MAP.get(cp) : -1;

    if (vsB !== -1) {
      vsBytes.push(vsB);
      invisibleCount++;
      if (microscope.length < 160) {
        microscope.push({ index: totalCodePoints, kind: 'vs256', cpHex: `U+${cp.toString(16).toUpperCase()}`, label: describeCodePoint(cp), byteVal: vsB });
      }
    } else if (zwQ !== -1) {
      zwQuats.push(zwQ);
      invisibleCount++;
      if (microscope.length < 160) {
        microscope.push({ index: totalCodePoints, kind: 'zw4', cpHex: `U+${cp.toString(16).toUpperCase()}`, label: describeCodePoint(cp), dibit: zwQ });
      }
    } else if (INVISIBLE_NAMES.has(cp)) {
      invisibleCount++;
      if (microscope.length < 160) {
        microscope.push({ index: totalCodePoints, kind: 'other-zw', cpHex: `U+${cp.toString(16).toUpperCase()}`, label: describeCodePoint(cp) });
      }
    } else {
      visibleChars += ch;
      if (microscope.length < 160) {
        microscope.push({ index: totalCodePoints, kind: 'visible', char: ch, cpHex: `U+${cp.toString(16).toUpperCase().padStart(4, '0')}` });
      }
    }
    totalCodePoints++;
  }

  let detectedMode = null;
  let rawEnvelope = null;

  if (vsBytes.length >= 7) {
    detectedMode = 'vs256';
    rawEnvelope = Buffer.from(vsBytes);
  } else if (zwQuats.length >= 28) {
    detectedMode = 'zw4';
    const byteLen = Math.floor(zwQuats.length / 4);
    const out = Buffer.alloc(byteLen);
    for (let i = 0; i < byteLen; i++) {
      out[i] = (
        (zwQuats[i * 4] << 6) |
        (zwQuats[i * 4 + 1] << 4) |
        (zwQuats[i * 4 + 2] << 2) |
        zwQuats[i * 4 + 3]
      ) & 0xff;
    }
    rawEnvelope = out;
  }

  const hexPreview = rawEnvelope
    ? Array.from(rawEnvelope.subarray(0, 64)).map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join(' ')
    : '';

  if (!rawEnvelope) {
    return {
      hasInvisible: invisibleCount > 0,
      detectedMode: null,
      visibleText: visibleChars,
      stats: {
        visibleChars: Array.from(visibleChars).length,
        totalCodePoints,
        invisibleCodePoints: invisibleCount,
        utf16Length: str.length
      },
      microscope,
      hexPreview: '',
      decoded: {
        valid: false,
        error: invisibleCount > 0
          ? `Phát hiện ${invisibleCount} ký tự ẩn lẻ tẻ nhưng chưa đủ độ dài bản tin mật.`
          : 'Văn bản sạch — không phát hiện ký tự tàng hình nào.'
      }
    };
  }

  const unpacked = unpackEnvelope(rawEnvelope, password);
  return {
    hasInvisible: true,
    detectedMode,
    visibleText: visibleChars,
    stats: {
      visibleChars: Array.from(visibleChars).length,
      totalCodePoints,
      invisibleCodePoints: invisibleCount,
      utf16Length: str.length,
      envelopeBytes: rawEnvelope.length
    },
    microscope,
    hexPreview,
    decoded: unpacked
  };
}

function generateCanaryBatch({
  coverText,
  recipients = [],
  secretNote = 'Tài liệu Mật nội bộ - Nghiêm cấm sao chép ra ngoài',
  password = '',
  mode = 'vs256'
}) {
  const cleanList = recipients
    .map((r) => String(r || '').trim())
    .filter(Boolean)
    .slice(0, 50);

  const batchId = 'CNRY-' + crypto.randomBytes(3).toString('hex').toUpperCase();
  const taggedAt = new Date().toISOString();

  const items = cleanList.map((recipient, idx) => {
    const fingerprint = crypto
      .createHash('sha256')
      .update(`${batchId}:${idx}:${recipient}:${taggedAt}`)
      .digest('hex')
      .slice(0, 12)
      .toUpperCase();

    const canaryMeta = {
      batchId,
      recipient,
      slot: idx + 1,
      fingerprint,
      taggedAt
    };

    const encoded = encodeZeroWidth({
      coverText,
      secretText: secretNote,
      password,
      mode,
      canaryMeta
    });

    return {
      recipient,
      fingerprint,
      batchId,
      taggedAt,
      stegoText: encoded.stegoText,
      stats: encoded.stats
    };
  });

  return { batchId, taggedAt, count: items.length, items };
}

module.exports = {
  crc32,
  encodeZeroWidth,
  inspectAndDecodeZeroWidth,
  generateCanaryBatch,
  stripInvisibleStego
};
