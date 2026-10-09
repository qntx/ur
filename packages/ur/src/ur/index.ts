import * as bytewords from "../bytewords/index.ts";
import { UrError, fail } from "../error.ts";
import type { UrErrorInfo, UrLimit } from "../error.ts";
import {
  FountainDecoder,
  FountainEncoder,
  decodePart,
  encodePart,
  mergeLimits,
} from "../fountain/index.ts";
import type { DecoderLimits } from "../fountain/index.ts";
import { parse } from "./parse.ts";
import type { Kind, ParsedUr } from "./parse.ts";
import { UrType } from "./type.ts";

export type { DecoderLimits } from "../fountain/index.ts";
export { normalizeUr, parse, parseNormalized } from "./parse.ts";
export type { Kind, ParsedUr } from "./parse.ts";
export { UrType } from "./type.ts";

/** Encode a single-part UR. Empty data is allowed. */
export function encode(data: Uint8Array, type: UrType): string {
  const body = bytewords.encode(data, "minimal");
  return `ur:${type.value}/${body}`;
}

/**
 * Decode payload from a single- or multi-part UR. Multi-part returns the CBOR-encoded fountain part
 * bytes, not the message.
 */
export function decode(uri: string): { kind: Kind; payload: Uint8Array } {
  const parsed = parse(uri);
  const payload = bytewords.decode(parsed.body, "minimal");
  return { kind: parsed.kind, payload };
}

/** Like {@link decode} but retains the normalized type. */
export function decodeWithType(uri: string): {
  type: UrType;
  kind: Kind;
  payload: Uint8Array;
} {
  const parsed = parse(uri);
  const payload = bytewords.decode(parsed.body, "minimal");
  return { type: parsed.type, kind: parsed.kind, payload };
}

/** Decode a single-part UR payload. Multi-part URIs throw `NotSinglePart`. */
export function decodeMessage(uri: string): Uint8Array {
  const { kind, payload } = decode(uri);
  if (kind !== "single") {
    fail("NotSinglePart");
  }
  return payload;
}

/** Uppercase UR string for denser QR alphanumeric mode. */
export function toQrString(uri: string): string {
  return uri.toUpperCase();
}

/** UR encoder. `K == 1` emits single-part; otherwise fountain. */
export class Encoder {
  private readonly fountain: FountainEncoder;
  private readonly urType: UrType;
  private readonly message: Uint8Array;
  private singleEmitted = false;

  private constructor(fountain: FountainEncoder, urType: UrType, message: Uint8Array) {
    this.fountain = fountain;
    this.urType = urType;
    this.message = message;
  }

  static create(
    message: Uint8Array,
    maxFragmentLength: number,
    type: UrType,
    options?: { minFragmentLength?: number; firstSequence?: number },
  ): Encoder {
    return new Encoder(
      new FountainEncoder(message, { maxFragmentLength, ...options }),
      type,
      // copy: later mutation of the caller buffer must not change K==1 output
      new Uint8Array(message),
    );
  }

  static bytes(
    message: Uint8Array,
    maxFragmentLength: number,
    options?: { minFragmentLength?: number; firstSequence?: number },
  ): Encoder {
    return Encoder.create(message, maxFragmentLength, UrType.bytes(), options);
  }

  get isSinglePart(): boolean {
    return this.fountain.fragmentCount === 1;
  }

  get fragmentCount(): number {
    return this.fountain.fragmentCount;
  }

  get currentIndex(): number {
    return this.isSinglePart ? (this.singleEmitted ? 1 : 0) : this.fountain.sequence;
  }

  get complete(): boolean {
    return this.isSinglePart ? this.singleEmitted : this.fountain.isComplete;
  }

  nextPart(): string {
    if (this.isSinglePart) {
      this.singleEmitted = true;
      return encode(this.message, this.urType);
    }
    const { value: part } = this.fountain.next();
    if (part === undefined) {
      fail("Internal");
    }
    const body = bytewords.encode(encodePart(part), "minimal");
    return `ur:${this.urType.value}/${part.sequence}-${part.sequenceCount}/${body}`;
  }
}

/** UR decoder with type stickiness and URI limits. */
export class Decoder {
  private readonly fountain: FountainDecoder;
  private readonly limits: DecoderLimits;
  private readonly expectedType: UrType | undefined;
  private seenType: UrType | undefined;
  private single: Uint8Array | undefined;
  private poisoned: UrErrorInfo | undefined;

  constructor(options?: { limits?: Partial<DecoderLimits>; expectedType?: UrType }) {
    const limits = mergeLimits(options?.limits);
    this.fountain = new FountainDecoder(limits);
    this.limits = limits;
    this.expectedType = options?.expectedType;
  }

  private poisonLimit(limit: UrLimit): never {
    const info: UrErrorInfo = { code: "ResourceLimit", limit };
    this.poisoned = info;
    fail(info);
  }

  private escalate(e: unknown): never {
    if (e instanceof UrError && (e.info.code === "ResourceLimit" || e.info.code === "Internal")) {
      this.poisoned ??= e.info;
    }
    throw e;
  }

  get poisonState(): UrErrorInfo | undefined {
    return this.poisoned ?? this.fountain.poisonState;
  }

  receive(uri: string): void {
    if (this.poisoned) {
      throw new UrError(this.poisoned);
    }
    if (this.fountain.isPoisoned) {
      const poison = this.fountain.poisonState;
      if (poison === undefined) {
        fail("Internal");
      }
      this.poisoned ??= poison;
      throw new UrError(poison);
    }
    if (uri.length > this.limits.maxUriLen) {
      this.poisonLimit("uriLength");
    }

    const parsed = parse(uri);
    if (this.expectedType && !parsed.type.equals(this.expectedType)) {
      fail({
        code: "UnexpectedType",
        expected: [this.expectedType],
        found: parsed.type,
      });
    }
    if (this.seenType && !this.seenType.equals(parsed.type)) {
      fail({
        code: "UnexpectedType",
        expected: [this.seenType],
        found: parsed.type,
      });
    }

    try {
      if (parsed.kind === "single") {
        this.receiveSingle(parsed);
      } else {
        this.receiveFountain(parsed);
      }
    } catch (error) {
      this.escalate(error);
    }
  }

  private receiveSingle(parsed: ParsedUr): void {
    if (this.fountain.resolvedFragmentCount() !== undefined) {
      fail("InconsistentPart");
    }
    if (this.single !== undefined) {
      return;
    }
    const data = bytewords.decode(parsed.body, "minimal");
    if (data.length > this.limits.maxMessageLength) {
      this.poisonLimit("messageLength");
    }
    this.seenType = parsed.type;
    this.single = data;
  }

  private receiveFountain(parsed: ParsedUr): void {
    if (this.single !== undefined) {
      fail("InconsistentPart");
    }
    const decoded = bytewords.decode(parsed.body, "minimal");
    const part = decodePart(decoded, this.limits);
    const { indices } = parsed;
    if (!indices) {
      fail("InvalidIndices");
    }
    if (part.sequence !== indices.seq || part.sequenceCount !== indices.count) {
      fail("InvalidIndices");
    }
    this.fountain.receive(part);
    this.seenType ??= parsed.type;
  }

  get complete(): boolean {
    return this.single !== undefined || this.fountain.complete;
  }

  message(): Uint8Array | undefined {
    if (this.poisoned) {
      throw new UrError(this.poisoned);
    }
    if (this.fountain.isPoisoned) {
      const poison = this.fountain.poisonState;
      if (poison === undefined) {
        fail("Internal");
      }
      throw new UrError(poison);
    }
    if (this.single) {
      return new Uint8Array(this.single);
    }
    return this.fountain.message();
  }

  resolvedFragmentCount(): number | undefined {
    if (this.single) {
      return 1;
    }
    return this.fountain.resolvedFragmentCount();
  }

  get fragmentCount(): number {
    return this.single ? 1 : this.fountain.fragmentCount;
  }

  get type(): UrType | undefined {
    return this.seenType;
  }

  get isPoisoned(): boolean {
    return this.poisoned !== undefined || this.fountain.isPoisoned;
  }
}
