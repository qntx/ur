import * as bytewords from "../bytewords/index.ts";
import { UrError, fail } from "../error.ts";
import type { UrErrorInfo } from "../error.ts";
import {
  FountainDecoder,
  FountainEncoder,
  decodePart,
  encodePart,
  mergeLimits,
} from "../fountain/index.ts";
import type { DecoderLimits, DecoderState, Progress, ReceiveResult } from "../fountain/index.ts";
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

/** Reconstructed UR payload and type: the terminal value of {@link UrDecoder}. */
export type DecodedUr = Readonly<{ type: UrType; message: Uint8Array }>;

/** {@link UrDecoder} options; `accept` empty accepts any type. */
export type UrDecoderOptions = Readonly<{
  limits?: Partial<DecoderLimits>;
  accept?: ReadonlyArray<UrType>;
}>;

type Terminal =
  | Readonly<{ phase: "complete"; value: DecodedUr }>
  | Readonly<{ phase: "failed"; error: UrError }>;

function toUrError(error: unknown): UrError {
  return error instanceof UrError ? error : new UrError({ code: "Internal" });
}

/**
 * UR decoder (single-part or fountain).
 *
 * `receive` never throws for frame problems: parse, type, index, bytewords, and consistency
 * failures come back `rejected` with the session unchanged; limit violations and completion-check
 * failures are `fatal` and move the session to `failed`. Terminal sessions return `duplicate` for
 * every further frame without parsing it (UR-ADR-014). The first successfully ingested frame locks
 * the UR type.
 */
export class UrDecoder {
  readonly #limits: DecoderLimits;
  readonly #accept: ReadonlyArray<UrType>;
  #fountain: FountainDecoder;
  #lockedType: UrType | undefined;
  #terminal: Terminal | undefined;
  #processed = 0;

  constructor(options?: UrDecoderOptions) {
    this.#limits = mergeLimits(options?.limits);
    this.#fountain = new FountainDecoder({ limits: this.#limits });
    this.#accept = options?.accept ?? [];
  }

  /** Receive one UR string (single-part or fountain part). */
  receive(text: string): ReceiveResult {
    if (this.#terminal !== undefined) {
      this.#processed += 1;
      return { status: "duplicate" };
    }
    if (text.length > this.#limits.maxUriLength) {
      return this.#fail({ code: "ResourceLimit", limit: "uriLength" });
    }
    try {
      return this.#receiveParsed(text);
    } catch (error) {
      const urError = toUrError(error);
      if (urError.fatal) {
        return this.#fatal(urError);
      }
      return { status: "rejected", error: urError };
    }
  }

  #receiveParsed(text: string): ReceiveResult {
    const parsed = parse(text);
    this.#checkType(parsed.type);
    return parsed.kind === "single" ? this.#receiveSingle(parsed) : this.#receiveFountain(parsed);
  }

  /** Type admission: `accept` list (when non-empty), then the locked type. */
  #checkType(type: UrType): void {
    if (this.#accept.length > 0 && !this.#accept.some((t) => t.equals(type))) {
      fail({ code: "UnexpectedType", expected: this.#accept, found: type });
    }
    const locked = this.#lockedType;
    if (locked !== undefined && !locked.equals(type)) {
      fail({ code: "UnexpectedType", expected: [locked], found: type });
    }
  }

  #receiveSingle(parsed: ParsedUr): ReceiveResult {
    // A single-part URI inside a collecting fountain session is inconsistent;
    // the reverse order is unreachable (a completed session is terminal).
    if (this.#fountain.state.phase !== "empty") {
      fail("InconsistentPart");
    }
    const data = bytewords.decode(parsed.body, "minimal");
    if (data.length > this.#limits.maxMessageLength) {
      return this.#fail({ code: "ResourceLimit", limit: "messageLength" });
    }
    this.#lockedType ??= parsed.type;
    this.#terminal = { phase: "complete", value: { type: parsed.type, message: data } };
    this.#processed += 1;
    return { status: "accepted" };
  }

  #receiveFountain(parsed: ParsedUr): ReceiveResult {
    const decoded = bytewords.decode(parsed.body, "minimal");
    const part = decodePart(decoded, this.#limits);
    const { indices } = parsed;
    if (
      indices === undefined ||
      part.sequence !== indices.seq ||
      part.sequenceCount !== indices.count
    ) {
      fail("InvalidIndices");
    }
    const result = this.#fountain.receive(part);
    if (result.status === "rejected") {
      return result;
    }
    if (result.status === "fatal") {
      this.#terminal = { phase: "failed", error: result.error };
      return result;
    }
    this.#lockedType ??= parsed.type;
    this.#processed += 1;
    const fountainState = this.#fountain.state;
    if (fountainState.phase === "complete") {
      this.#terminal = {
        phase: "complete",
        value: { type: parsed.type, message: fountainState.value },
      };
    }
    return result;
  }

  /** Moves the session to `failed` with a built error and returns `fatal`. */
  #fail(info: UrErrorInfo): ReceiveResult {
    return this.#fatal(new UrError(info));
  }

  /** Moves the session to `failed` with an existing error and returns `fatal`. */
  #fatal(error: UrError): ReceiveResult {
    this.#terminal = { phase: "failed", error };
    return { status: "fatal", error };
  }

  /** Current session state. */
  get state(): DecoderState<DecodedUr> {
    const terminal = this.#terminal;
    if (terminal !== undefined) {
      return terminal.phase === "complete"
        ? { phase: "complete", value: terminal.value }
        : { phase: "failed", error: terminal.error };
    }
    const fountain = this.#fountain.state;
    return fountain.phase === "collecting"
      ? { phase: "collecting", progress: fountain.progress }
      : { phase: "empty" };
  }

  /**
   * Progress snapshot (`empty` reports all zeros; a session completed via a single-part URI reports
   * `K = 1`).
   */
  get progress(): Progress {
    const base = this.#fountain.progress;
    if (base.fragmentCount === 0 && this.#terminal?.phase === "complete") {
      return { fragmentCount: 1, rank: 1, recovered: 1, processed: this.#processed, ratio: 1 };
    }
    return {
      fragmentCount: base.fragmentCount,
      rank: base.rank,
      recovered: base.recovered,
      processed: this.#processed,
      ratio: base.ratio,
    };
  }

  /** Fragment indexes of the most recent `accepted`/`duplicate` part. */
  get lastIndexes(): ReadonlyArray<number> {
    return this.#fountain.lastIndexes;
  }

  /** Returns the session to `empty`; limits and the `accept` list are kept. */
  reset(): void {
    this.#fountain = new FountainDecoder({ limits: this.#limits });
    this.#lockedType = undefined;
    this.#terminal = undefined;
    this.#processed = 0;
  }
}
