import { cbor, decodeCbor, encodeCbor, CborError } from "@blockchaincommons/dcbor";
import type { Cbor, CborInput } from "@blockchaincommons/dcbor";

import { fail } from "../error.ts";
import { UrType, decodeWithType, encode, toQrString } from "../ur/index.ts";

export function mapCborDecode<T>(run: () => T): T {
  try {
    return run();
  } catch (error) {
    if (CborError.isCborError(error)) {
      fail("CborDecode", { cause: error });
    }
    throw error;
  }
}

export function mapCborType<T>(run: () => T): T {
  try {
    return run();
  } catch (error) {
    if (CborError.isCborError(error)) {
      fail("CborType", { cause: error });
    }
    throw error;
  }
}

function parseType(type: UrType | string): UrType {
  return typeof type === "string" ? UrType.parse(type) : type;
}

/** Uniform Resource whose payload is deterministic CBOR. */
export class Ur {
  readonly type: UrType;
  readonly cbor: Cbor;

  private constructor(type: UrType, cborValue: Cbor) {
    this.type = type;
    this.cbor = cborValue;
  }

  static create(type: UrType | string, input: CborInput): Ur {
    // copy: caller mutation must not change the stored bstr
    const prepared = input instanceof Uint8Array ? new Uint8Array(input) : input;
    return new Ur(
      parseType(type),
      mapCborType(() => cbor(prepared)),
    );
  }

  /** Wrap already-encoded dCBOR bytes. Used by fromUrString. */
  static fromCborData(type: UrType | string, data: Uint8Array): Ur {
    // copy: caller mutation must not change the stored bstr
    const bytes = new Uint8Array(data);
    const value = mapCborDecode(() => decodeCbor(bytes));
    return new Ur(parseType(type), value);
  }

  static fromUrString(uri: string): Ur {
    const { type, kind, payload } = decodeWithType(uri);
    if (kind !== "single") {
      fail("NotSinglePart");
    }
    return Ur.fromCborData(type, payload);
  }

  string(): string {
    const bytes = mapCborType(() => encodeCbor(this.cbor));
    return encode(bytes, this.type);
  }

  qrString(): string {
    return toQrString(this.string());
  }

  checkType(expected: UrType | string): void {
    const want = parseType(expected);
    if (!this.type.equals(want)) {
      fail({ code: "UnexpectedType", expected: [want], found: this.type });
    }
  }
}
