import { cbor, decodeCbor, encodeCbor, CborError } from "@blockchaincommons/dcbor";
import type { Cbor, CborInput } from "@blockchaincommons/dcbor";

import { fail } from "../error.ts";
import { UrEncoder, encodeUr, parseUr, parseUrType, toQrString } from "../ur/index.ts";
import type { DecodedUr, UrEncoderOptions, UrType } from "../ur/index.ts";

function mapCborDecode<T>(run: () => T): T {
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

/** Uniform Resource whose payload is deterministic CBOR. */
export class Ur {
  readonly type: UrType;
  readonly cbor: Cbor;

  private constructor(type: UrType, cborValue: Cbor) {
    this.type = type;
    this.cbor = cborValue;
  }

  static fromCbor(type: UrType | string, input: CborInput): Ur {
    // copy: caller mutation must not change the stored bstr
    const prepared = input instanceof Uint8Array ? new Uint8Array(input) : input;
    return new Ur(
      parseUrType(type),
      mapCborType(() => cbor(prepared)),
    );
  }

  /** Wrap already-encoded dCBOR bytes. */
  static fromCborData(type: UrType | string, data: Uint8Array): Ur {
    // copy: caller mutation must not change the stored bstr
    const bytes = new Uint8Array(data);
    const value = mapCborDecode(() => decodeCbor(bytes));
    return new Ur(parseUrType(type), value);
  }

  /** Parse a **single-part** UR string; the message must be dCBOR. */
  static parse(text: string): Ur {
    const parsed = parseUr(text);
    if (parsed.kind !== "single") {
      fail("NotSinglePart");
    }
    return Ur.fromCborData(parsed.type, parsed.message);
  }

  /** Wrap a completed {@link UrDecoder} result; the message must be dCBOR. */
  static fromDecoded(decoded: DecodedUr): Ur {
    return Ur.fromCborData(decoded.type, decoded.message);
  }

  toCborData(): Uint8Array {
    return mapCborType(() => encodeCbor(this.cbor));
  }

  toString(): string {
    return encodeUr(this.type, this.toCborData());
  }

  toQrString(): string {
    return toQrString(this.toString());
  }

  /** L3 encoder over this UR's dCBOR bytes. */
  encoder(options: UrEncoderOptions): UrEncoder {
    return new UrEncoder(this.type, this.toCborData(), options);
  }
}
