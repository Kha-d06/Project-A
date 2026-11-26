/**
 * QR codes in email images, decoded on this computer ("quishing": a QR code
 * hides its destination from link checks and is usually scanned on a phone,
 * outside the computer's protection).
 *
 * The image is untrusted input, so decoding is bounded before any pixel is
 * allocated:
 *  - only PNG and JPEG, recognised by their signature, not the file name;
 *  - at most 8 MB per image and 10 images per message;
 *  - the width and height are read from the header first; anything over
 *    4096 pixels a side or 12 megapixels is skipped (decompression bombs);
 *  - JPEG decoding has its own resolution and memory caps;
 *  - large images are scaled down before the QR search, which bounds its time.
 * Pure JavaScript decoders (jsQR, pngjs, jpeg-js): no native code parses the image.
 * The decoded text is never opened or fetched; it is only checked.
 */
import jsQR from "jsqr";
import jpeg from "jpeg-js";
import { PNG } from "pngjs";

export const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
export const MAX_IMAGES = 10;
const MAX_SIDE = 4096;
const MAX_PIXELS = 12_000_000;
const SEARCH_SIDE = 1600;

export type ImageKind = "png" | "jpeg";

export function imageKind(bytes: Uint8Array): ImageKind | null {
  if (bytes.length > 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return "png";
  if (bytes.length > 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "jpeg";
  return null;
}

/** Width and height from the header alone, without decoding; null if unreadable. */
export function imageSize(bytes: Uint8Array): { width: number; height: number } | null {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const kind = imageKind(bytes);
  if (kind === "png") {
    if (bytes.length < 24) return null;
    return { width: view.getUint32(16), height: view.getUint32(20) };
  }
  if (kind === "jpeg") {
    // Walk the markers to the first start-of-frame (SOF0..SOF15, not DHT/JPG/DAC).
    let i = 2;
    while (i + 9 < bytes.length) {
      if (bytes[i] !== 0xff) return null;
      const marker = bytes[i + 1]!;
      if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
        i += 2;
        continue;
      }
      const length = view.getUint16(i + 2);
      if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
        return { width: view.getUint16(i + 7), height: view.getUint16(i + 5) };
      }
      if (length < 2) return null;
      i += 2 + length;
    }
  }
  return null;
}

function withinLimits(size: { width: number; height: number } | null): size is { width: number; height: number } {
  return !!size && size.width > 0 && size.height > 0 && size.width <= MAX_SIDE && size.height <= MAX_SIDE && size.width * size.height <= MAX_PIXELS;
}

/** RGBA pixels, or null for anything unsupported, oversized or malformed. */
export function decodePixels(bytes: Uint8Array): { data: Uint8ClampedArray; width: number; height: number } | null {
  if (bytes.length > MAX_IMAGE_BYTES || !withinLimits(imageSize(bytes))) return null;
  try {
    if (imageKind(bytes) === "png") {
      const png = PNG.sync.read(Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength));
      return { data: new Uint8ClampedArray(png.data.buffer, png.data.byteOffset, png.data.byteLength), width: png.width, height: png.height };
    }
    const img = jpeg.decode(bytes, { useTArray: true, formatAsRGBA: true, maxResolutionInMP: MAX_PIXELS / 1_000_000, maxMemoryUsageInMB: 256 });
    return { data: new Uint8ClampedArray(img.data.buffer, img.data.byteOffset, img.data.byteLength), width: img.width, height: img.height };
  } catch {
    return null;
  }
}

/** Nearest-neighbour scaling so the longest side is at most SEARCH_SIDE. */
function scaled(img: { data: Uint8ClampedArray; width: number; height: number }) {
  const factor = Math.max(img.width, img.height) / SEARCH_SIDE;
  if (factor <= 1) return img;
  const width = Math.max(1, Math.floor(img.width / factor));
  const height = Math.max(1, Math.floor(img.height / factor));
  const data = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < height; y++) {
    const sy = Math.min(img.height - 1, Math.floor(y * factor));
    for (let x = 0; x < width; x++) {
      const sx = Math.min(img.width - 1, Math.floor(x * factor));
      const from = (sy * img.width + sx) * 4;
      data.set(img.data.subarray(from, from + 4), (y * width + x) * 4);
    }
  }
  return { data, width, height };
}

/** The text of a QR code in the image, or null (no code, or not an image we decode). */
export function decodeQr(bytes: Uint8Array): string | null {
  const img = decodePixels(bytes);
  if (!img) return null;
  const tryDecode = (i: { data: Uint8ClampedArray; width: number; height: number }) => jsQR(i.data, i.width, i.height, { inversionAttempts: "attemptBoth" })?.data ?? null;
  const small = scaled(img);
  return tryDecode(small) ?? (small === img ? null : tryDecode(img.width * img.height <= 4_000_000 ? img : small));
}

/** Web addresses found in QR codes in a message's images (never opened). */
export function qrLinks(images: { content: Uint8Array; contentType?: string }[]): string[] {
  const out: string[] = [];
  for (const image of images.slice(0, MAX_IMAGES)) {
    const text = decodeQr(image.content)?.trim();
    if (text && /^https?:\/\//i.test(text) && !out.includes(text)) out.push(text.slice(0, 2048));
  }
  return out;
}
