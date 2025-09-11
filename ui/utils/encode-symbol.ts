/**
 * Encode a string into an 8-byte Uint8Array (like the Rust [u8; 8]).
 * - Copies up to the first 8 bytes of the string.
 * - Any remaining positions are filled with 0.
 */
export function encodeSymbolTo8Bytes(symbol: string): Uint8Array {
  const bytes = new Uint8Array(8);
  for (let i = 0; i < symbol.length && i < 8; i++) {
    bytes[i] = symbol.charCodeAt(i);
  }
  return bytes;
}

/**
 * Decode an 8-byte Uint8Array back into a string,
 * stopping at the first 0 byte (like Rust's null-terminating logic).
 */
export function decodeSymbolFrom8Bytes(bytes: Uint8Array | number[]): string {
  if (Array.isArray(bytes)) {
    bytes = new Uint8Array(bytes);
  }

  // Find the first zero byte
  let end = bytes.indexOf(0);
  if (end === -1) {
    end = bytes.length; // no zero found, use entire array
  }

  // Decode only up to `end`
  return new TextDecoder().decode(bytes.slice(0, end));
}
