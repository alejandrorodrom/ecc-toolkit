import { BINARY_ENC, HEX_ENC, UTF8_ENC } from "../constants";
import {
  bufferToHex as bufferToHexRaw,
  bufferToUtf8,
  hexToBuffer,
  utf8ToBuffer,
} from "./encoding";

const TYPE_BUFFER = "buffer";
const TYPE_ARRAY = "array";
const TYPE_TYPED_ARRAY = "typed-array";
const TYPE_ARRAY_BUFFER = "array-buffer";

/**
 * Rounds a length in **characters** (e.g. binary digits) up to the next multiple of `byteSize` (default 8).
 * Used to build fixed-width `0`/`1` or hex string layouts in the same way as **enc-utils**.
 *
 * @param length - Current length.
 * @param byteSize - Group size in characters; default `8` (one byte of binary digits).
 * @returns The smallest multiple of `byteSize` that is `>=` `length`, or `length` if already aligned.
 */
export function calcByteLength(length: number, byteSize = 8): number {
  const remainder = length % byteSize;
  return remainder
    ? ((length - remainder) / byteSize) * byteSize + byteSize
    : length;
}

/**
 * Pads a string to a minimum length on the **left** or **right** using a repeated `padding` string.
 * Base implementation for {@link padLeft} and {@link padRight}. If `str` is already longer than `length`,
 * it is returned unchanged (no truncation).
 *
 * @param str - Source string.
 * @param length - Target character length.
 * @param left - `true` to pad on the left, `false` on the right.
 * @param padding - Character or string to repeat; default `"0"`.
 * @returns Padded string.
 */
export function padString(
  str: string,
  length: number,
  left: boolean,
  padding = "0",
): string {
  const diff = length - str.length;
  let result = str;
  if (diff > 0) {
    const pad = padding.repeat(diff);
    result = left ? pad + str : str + pad;
  }
  return result;
}

/**
 * Left-pads a string to a minimum character length.
 *
 * @param str - Input string.
 * @param length - Target length (if `str` is longer, it is not truncated).
 * @param padding - Character or string repeated for padding (default `"0"`).
 * @returns Padded string.
 */
export function padLeft(str: string, length: number, padding = "0"): string {
  return padString(str, length, true, padding);
}

/**
 * Right-pads a string to a minimum character length.
 *
 * @param str - Input string.
 * @param length - Target length (if `str` is longer, it is not truncated).
 * @param padding - Character or string repeated for padding (default `"0"`).
 * @returns Padded string.
 */
export function padRight(str: string, length: number, padding = "0"): string {
  return padString(str, length, false, padding);
}

/**
 * Left-pads a `0`/`1` string with `padding` (default `0`) so the result length is a **multiple of `byteSize`**
 * (default 8). Empty input returns an empty string. Used by {@link numberToBinary} and {@link splitBytes}.
 *
 * @param str - Binary digit string.
 * @param byteSize - Bits per group; default `8`.
 * @param padding - Pad character; default `0`.
 */
export function sanitizeBytes(str: string, byteSize = 8, padding = "0"): string {
  return padLeft(str, calcByteLength(str.length, byteSize), padding);
}

/**
 * Splits a `0`/`1` string into chunks of `byteSize` characters after {@link sanitizeBytes} (default 8).
 * Produces the same groupings as the bytes derived from {@link binaryToArray}. Returns `[]` for empty input
 * (or if `String#match` cannot match, which is defensive for unusual environments).
 *
 * @param str - Binary digit string.
 * @param byteSize - Chunk width in characters; default `8`.
 * @returns Consecutive substrings, each one byte in binary form.
 */
export function splitBytes(str: string, byteSize = 8): string[] {
  const padded = sanitizeBytes(str, byteSize);
  if (padded.length === 0) {
    return [];
  }
  const m = padded.match(new RegExp(`.{${byteSize}}`, "gi"));
  if (m == null) {
    return [];
  }
  return Array.from(m);
}

/**
 * Decodes a binary string of `0`/`1` (internally {@link sanitizeBytes} / {@link splitBytes} to full bytes) into a
 * `Uint8Array`. An empty string yields an empty `Uint8Array`.
 *
 * @param bin - `0`/`1` string; non-empty input should have length a multiple of 8 for typical enc-utils behavior.
 */
export function binaryToArray(bin: string): Uint8Array {
  return new Uint8Array(splitBytes(bin).map((x) => Number.parseInt(x, 2)));
}

/**
 * Encodes a number as **unsigned 32-bit** (`num >>> 0`), then minimal base-2 without leading zero padding
 * in the *integer* part, then {@link sanitizeBytes} to a whole number of 8-bit groups. Same layout as
 * **enc-utils**; used by {@link numberToArray} and {@link numberToHex}.
 *
 * @param num - Any number; only the low 32 unsigned bits are used.
 * @returns Padded `0`/`1` string.
 */
export function numberToBinary(num: number): string {
  const bin = (num >>> 0).toString(2);
  return sanitizeBytes(bin);
}

/**
 * Whether the value is a **non-empty** string of only `0`/`1` whose **length** is a multiple of 8.
 * This is the same rule as the “binary” branch in {@link getEncoding} (before {@link isHexString} and UTF-8).
 *
 * @param str - Value to test; non-strings and empty strings are `false`.
 * @returns `true` if the value matches the binary string pattern.
 */
export function isBinaryString(str: unknown): boolean {
  if (typeof str !== "string" || !/^[01]+$/.test(str)) {
    return false;
  }
  if (str.length % 8 !== 0) {
    return false;
  }
  return true;
}

/**
 * Whether the string is hex **with a `0x` prefix** and ASCII hex digits only.
 *
 * @remarks
 * Strict enc-utils rule: hex strings **without** `0x` return `false`.
 * The prefix must be exactly lowercase `0x` (not `0X`).
 *
 * @param str - Value to test.
 * @param length - When set, expected **byte** length: the string must be `2 + 2 * length` characters long.
 * @returns `true` if the pattern (and optional length) matches.
 */
export function isHexString(str: unknown, length?: number): boolean {
  if (typeof str !== "string" || !/^0x[0-9A-Fa-f]*$/.test(str)) {
    return false;
  }
  if (length !== undefined && str.length !== 2 + 2 * length) {
    return false;
  }
  return true;
}

/**
 * Whether the value is a Node.js **`Buffer`** instance.
 *
 * @param val - Any value.
 * @returns `false` if `Buffer` is not defined in the environment; otherwise delegates to `Buffer.isBuffer`.
 */
export function isBuffer(val: unknown): boolean {
  if (typeof globalThis.Buffer === "undefined") {
    return false;
  }
  return globalThis.Buffer.isBuffer(val);
}

/**
 * Whether the value is an **ArrayBuffer view** (`TypedArray` / `DataView`), excluding `Buffer`.
 *
 * @param val - Any value.
 * @returns `true` for e.g. `Uint8Array`, `DataView`, etc., but not for `Buffer` or a bare `ArrayBuffer`.
 */
export function isTypedArray(val: unknown): boolean {
  return ArrayBuffer.isView(val) && !isBuffer(val);
}

/**
 * Whether the value is a bare **`ArrayBuffer`** (not a view or `Buffer`).
 *
 * @param val - Any value.
 */
export function isArrayBuffer(val: unknown): boolean {
  return !isTypedArray(val) && !isBuffer(val) && val instanceof ArrayBuffer;
}

/**
 * Type tag returned by {@link getType} for binary values, and `typeof` for everything else.
 */
export type EncLikeType =
  | "string"
  | "number"
  | "bigint"
  | "boolean"
  | "symbol"
  | "undefined"
  | "object"
  | "function"
  | typeof TYPE_BUFFER
  | typeof TYPE_ARRAY
  | typeof TYPE_TYPED_ARRAY
  | typeof TYPE_ARRAY_BUFFER;

/**
 * Classifies a value: `Buffer`, typed views, `ArrayBuffer`, then JS arrays; otherwise `typeof val`.
 *
 * @param val - Value to classify.
 * @returns One of the {@link EncLikeType} tags.
 */
export function getType(val: unknown): EncLikeType {
  if (isBuffer(val)) {
    return TYPE_BUFFER;
  }
  if (isTypedArray(val)) {
    return TYPE_TYPED_ARRAY;
  }
  if (isArrayBuffer(val)) {
    return TYPE_ARRAY_BUFFER;
  }
  if (Array.isArray(val)) {
    return TYPE_ARRAY;
  }
  return typeof val as EncLikeType;
}

/**
 * Heuristic **string** “encoding”: binary, strict `0x` hex, or UTF-8 by default.
 *
 * @remarks
 * Check order: {@link isBinaryString} → {@link isHexString} → otherwise treat as UTF-8 text.
 *
 * @param str - Input string.
 * @returns `"binary"`, `"hex"`, or `"utf8"`.
 */
export function getEncoding(
  str: string,
): typeof BINARY_ENC | typeof HEX_ENC | typeof UTF8_ENC {
  if (isBinaryString(str)) {
    return BINARY_ENC;
  }
  if (isHexString(str)) {
    return HEX_ENC;
  }
  return UTF8_ENC;
}

/**
 * Ensures a `0x` prefix on a hex string (does not duplicate if it already starts with `0x`).
 *
 * @param hex - Hex with or without prefix (does not validate digits).
 */
export function addHexPrefix(hex: string): string {
  return hex.startsWith("0x") ? hex : `0x${hex}`;
}

/**
 * Strips a leading literal `0x` prefix (lowercase only). Does not change the rest of the string.
 *
 * @param hex - String that may start with `0x`.
 */
export function removeHexPrefix(hex: string): string {
  return hex.replace(/^0x/, "");
}

/**
 * Copies bytes into a **new** `Uint8Array` (same idea as enc-utils `bufferToArray`).
 *
 * @param buf - Source bytes (typically `Uint8Array`).
 */
export function bufferToArray(buf: Uint8Array): Uint8Array {
  return new Uint8Array(buf);
}

/**
 * Interprets all bytes as one **unsigned** **big-endian** integer (MSB first).
 *
 * @remarks
 * Empty input returns `0`. With many bytes the value may exceed `2^53 - 1`;
 * JavaScript numbers then lose integer precision.
 *
 * @param buf - Byte sequence to interpret.
 */
export function bufferToNumber(buf: Uint8Array): number {
  if (buf.length === 0) {
    return 0;
  }
  let n = 0;
  for (const byte of buf) {
    n = (n << 8) | byte;
  }
  return n;
}

/**
 * Copies an octet `ArrayLike` into a new `Uint8Array`.
 *
 * @remarks
 * Historical name `arrayToBuffer`; here the result is always `Uint8Array`, not Node `Buffer`.
 *
 * @param arr - Indexable bytes or octets (e.g. `Uint8Array`, `number[]`).
 */
export function arrayToBuffer(arr: ArrayLike<number>): Uint8Array {
  return Uint8Array.from(arr);
}

/**
 * Encodes bytes as lowercase hex, with an optional `0x` prefix.
 *
 * @param arr - Bytes to encode.
 * @param prefixed - If `true`, prepends `0x` to the unprefixed hex.
 */
export function arrayToHex(arr: Uint8Array, prefixed = false): string {
  const hex = bufferToHexRaw(arr);
  return prefixed ? addHexPrefix(hex) : hex;
}

/**
 * Decodes UTF-8 bytes to a text string.
 *
 * @param arr - Valid UTF-8 bytes.
 */
export function arrayToUtf8(arr: Uint8Array): string {
  return bufferToUtf8(arr);
}

/**
 * Same as {@link bufferToNumber} applied to `arr`.
 *
 * @param arr - Big-endian bytes.
 */
export function arrayToNumber(arr: Uint8Array): number {
  return bufferToNumber(arr);
}

/**
 * Decodes hex to bytes. Optional `0x` prefix; delegates to {@link hexToBuffer}.
 *
 * @param hex - Hex string (same rules as `hexToBuffer` in the `encoding` module).
 * @throws If the hex is invalid (odd length, non-hex characters, etc.).
 */
export function hexToArray(hex: string): Uint8Array {
  return new Uint8Array(hexToBuffer(hex));
}

/**
 * Decodes hex to bytes and interprets them as **UTF-8** to produce a string.
 *
 * @param hex - Hex of the UTF-8 payload.
 * @throws If the hex or UTF-8 bytes are invalid.
 */
export function hexToUtf8(hex: string): string {
  return bufferToUtf8(hexToBuffer(hex));
}

/**
 * Encodes UTF-8 text to bytes (explicit copy in a new `Uint8Array`).
 *
 * @remarks
 * Practically equivalent to {@link utf8ToBuffer} from the `encoding` module, with a defensive copy.
 *
 * @param utf8 - JavaScript Unicode string (encoded as UTF-8).
 */
export function utf8ToArray(utf8: string): Uint8Array {
  return new Uint8Array(utf8ToBuffer(utf8));
}

/**
 * Encodes UTF-8 text to lowercase hex, with an optional `0x` prefix.
 *
 * @param utf8 - Input text.
 * @param prefixed - If `true`, result includes a `0x` prefix.
 */
export function utf8ToHex(utf8: string, prefixed = false): string {
  return arrayToHex(utf8ToBuffer(utf8), prefixed);
}

/**
 * Parses a base-**10** integer from a UTF-8 string.
 *
 * @param utf8 - Decimal string (e.g. `"42"`).
 * @returns A safe integer.
 * @throws If parsing does not yield a finite integer in JS safe range.
 */
export function utf8ToNumber(utf8: string): number {
  const num = Number.parseInt(utf8, 10);
  if (!Number.isFinite(num) || !Number.isSafeInteger(num)) {
    throw new Error("utf8ToNumber: value is not a safe integer");
  }
  return num;
}

/**
 * Converts a number as **uint32** (`num >>> 0`) to minimal big-endian bytes
 * (bit string padded to a multiple of 8 bits, same logic as enc-utils).
 *
 * @param num - Numeric value; only the low 32 unsigned bits are used.
 */
export function numberToArray(num: number): Uint8Array {
  return binaryToArray(numberToBinary(num));
}

/**
 * Same as {@link numberToArray} (copy in a new `Uint8Array`).
 *
 * @param num - See {@link numberToArray}.
 */
export function numberToBuffer(num: number): Uint8Array {
  return Uint8Array.from(numberToArray(num));
}

/**
 * Lowercase hex of the byte layout produced by {@link numberToArray} for `num`, with an optional `0x` prefix.
 *
 * @param num - Integer; uint32 projection as in enc-utils.
 * @param prefixed - Defaults to `false` when omitted.
 */
export function numberToHex(num: number, prefixed?: boolean): string {
  return arrayToHex(numberToArray(num), prefixed ?? false);
}

/**
 * Converts the number to its decimal string form (`String(num)`).
 *
 * @param num - Input number.
 */
export function numberToUtf8(num: number): string {
  return `${num}`;
}

/**
 * Trims from the **left** to at most `length` bytes: keeps the **tail** of the buffer.
 *
 * @remarks
 * If `data.length <= length`, returns `data` unchanged (same reference).
 *
 * @param data - Byte sequence.
 * @param length - Maximum number of bytes in the result.
 */
export function trimLeft(data: Uint8Array, length: number): Uint8Array {
  const diff = data.length - length;
  if (diff > 0) {
    return data.slice(diff);
  }
  return data;
}

/**
 * Trims from the **right**: keeps the first `length` bytes.
 *
 * @remarks
 * If `length` is greater than the current length, `slice` returns the whole buffer.
 *
 * @param data - Byte sequence.
 * @param length - Number of bytes to keep from the start.
 */
export function trimRight(data: Uint8Array, length: number): Uint8Array {
  return data.slice(0, length);
}
