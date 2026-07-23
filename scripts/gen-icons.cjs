// 生成简单的占位图标：深色底 + 亮色对角条纹，带 "盾形" 渐变效果
// 纯手工构造 PNG（IHDR/IDAT/IEND），不依赖任何第三方库
const zlib = require("zlib");
const fs = require("fs");
const path = require("path");

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function makePng(size) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type RGBA
  // 10/11/12 = 0 (compression/filter/interlace)

  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    const rowStart = y * (size * 4 + 1);
    raw[rowStart] = 0; // filter: none
    for (let x = 0; x < size; x++) {
      const off = rowStart + 1 + x * 4;
      // 深色背景
      let r = 24, g = 27, b = 38, a = 255;
      // 中央画一个亮青色"护盾"形状（上半宽、下半收窄）
      const cx = x / size - 0.5;
      const cy = y / size;
      const half = cy < 0.55 ? 0.28 : 0.28 * (1 - (cy - 0.55) / 0.45);
      if (Math.abs(cx) < half && cy > 0.15 && cy < 0.9) {
        const t = cy;
        r = Math.round(64 + 40 * t);
        g = Math.round(200 - 60 * t);
        b = Math.round(220 - 40 * t);
      }
      raw[off] = r; raw[off + 1] = g; raw[off + 2] = b; raw[off + 3] = a;
    }
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function makeIco(png, size) {
  // ICO 可直接内嵌 PNG 数据（Windows Vista+ 支持）
  const header = Buffer.alloc(6);
  header.writeUInt16LE(1, 2); // type: icon
  header.writeUInt16LE(1, 4); // count: 1
  const entry = Buffer.alloc(16);
  entry[0] = size >= 256 ? 0 : size; // width (0 = 256)
  entry[1] = size >= 256 ? 0 : size; // height
  entry.writeUInt16LE(1, 4); // planes
  entry.writeUInt16LE(32, 6); // bit count
  entry.writeUInt32LE(png.length, 8);
  entry.writeUInt32LE(22, 12); // image offset = 6 + 16
  return Buffer.concat([header, entry, png]);
}

const outDir = path.join(__dirname, "..", "src-tauri", "icons");
fs.mkdirSync(outDir, { recursive: true });
const png128 = makePng(128);
for (const size of [32, 128]) {
  const file = path.join(outDir, size === 32 ? "32x32.png" : "128x128.png");
  fs.writeFileSync(file, makePng(size));
  console.log("written", file);
}
fs.writeFileSync(path.join(outDir, "icon.ico"), makeIco(png128, 128));
console.log("written", path.join(outDir, "icon.ico"));
