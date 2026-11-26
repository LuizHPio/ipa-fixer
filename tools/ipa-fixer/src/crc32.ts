/** Initial state for streaming IEEE 802.3 CRC-32 calculation. */
export const CRC32_INIT = 0xffffffff;

const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  CRC_TABLE[i] = c >>> 0;
}

/**
 * Updates a running CRC-32 state with an additional byte chunk.
 */
export function crc32Update(crc: number, data: Uint8Array): number {
  let current = crc >>> 0;
  for (let i = 0; i < data.length; i++) {
    const byte = data[i]!;
    current = (CRC_TABLE[(current ^ byte) & 0xff]! ^ (current >>> 8)) >>> 0;
  }
  return current >>> 0;
}

/**
 * Finalizes a running CRC-32 state into the unsigned 32-bit checksum.
 */
export function crc32Finalize(crc: number): number {
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Computes the IEEE 802.3 CRC-32 checksum for a single buffer.
 */
export function crc32(data: Uint8Array): number {
  return crc32Finalize(crc32Update(CRC32_INIT, data));
}
