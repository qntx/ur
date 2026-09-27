import {
  MultipartDecoder,
  MultipartEncoder,
  fromUr,
  psbtCodec,
  seedCodec,
  toUr,
  toUrString,
} from "@qntx/ur/registry";
import type { Ur } from "@qntx/ur/registry";

export const SEED_ENTROPY_BYTES = 16;
export const PSBT_MAX_FRAGMENT_LENGTH = 50;

const HEX = /^(?:[0-9a-f]{2})+$/;

export function parseHex(input: string): Uint8Array {
  const hex = input.replaceAll(/\s+/g, "").toLowerCase();
  if (!HEX.test(hex)) {
    throw new TypeError("invalid hex");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

export function randomBytes(n: number): Uint8Array {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function encodeSeed(payload: Uint8Array): string {
  return toUrString({ payload }, seedCodec);
}

export function encodePsbtParts(bytes: Uint8Array): string[] {
  const encoder = MultipartEncoder.create(toUr({ bytes }, psbtCodec), PSBT_MAX_FRAGMENT_LENGTH);
  const n = encoder.isSinglePart ? 1 : encoder.fragmentCount;
  const parts: string[] = [];
  for (let i = 0; i < n; i++) {
    parts.push(encoder.nextPart());
  }
  return parts;
}

export function decodeSeed(text: string): Uint8Array {
  return fromUr(urFromParts(text), seedCodec).payload;
}

export function decodePsbt(text: string): Uint8Array {
  return fromUr(urFromParts(text), psbtCodec).bytes;
}

function urFromParts(text: string): Ur {
  const parts = text.split(/[\s,]+/).filter((part) => part.length > 0);
  if (parts.length === 0) {
    throw new TypeError("empty UR");
  }
  const decoder = new MultipartDecoder();
  for (const part of parts) {
    decoder.receive(part);
  }
  const ur = decoder.message();
  if (ur === undefined) {
    throw new TypeError("incomplete UR");
  }
  return ur;
}
