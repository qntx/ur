import { encodeBytewords } from "../bytewords/index.ts";
import { UrError, fail } from "../error.ts";
import type { UrErrorInfo } from "../error.ts";
import { FountainDecoder, FountainEncoder, encodePart, mergeLimits } from "../fountain/index.ts";
import type {
  DecoderLimits,
  DecoderState,
  FountainEncoderOptions,
  Part,
  Progress,
  ReceiveResult,
} from "../fountain/index.ts";
import { parseUr } from "./parse.ts";
import type { UrType } from "./type.ts";

export type { DecoderLimits } from "../fountain/index.ts";
export { parseUr, type ParsedUr } from "./parse.ts";
export { isUrType, parseUrType, type UrType } from "./type.ts";

/** Encode a single-part UR. Empty `message` is allowed. */
export function encodeUr(type: UrType, message: Uint8Array): string {
  const body = encodeBytewords(message, "minimal");
  return `ur:${type}/${body}`;
}

/** Uppercase UR string for denser QR alphanumeric mode. */
export function toQrString(ur: string): string {
  return ur.toUpperCase();
}

/** {@link UrEncoder} options (fountain encoder options verbatim). */
export type UrEncoderOptions = FountainEncoderOptions;

/**
 * UR string encoder. `K == 1` emits the same single-part UR on every step; larger messages emit
 * `ur:<type>/<seq>-<count>/<bytewords>` fountain parts until sequence `0xFFFFFFFF`, where iteration
 * ends.
 */
export class UrEncoder implements IterableIterator<string> {
  readonly #type: UrType;
  readonly #fountain: FountainEncoder;
  readonly #single: string | undefined;
  #emitted = false;

  constructor(type: UrType, message: Uint8Array, options: UrEncoderOptions) {
    this.#type = type;
    this.#fountain = new FountainEncoder(message, options);
    // copy: later mutation of the caller buffer must not change K==1 output
    this.#single =
      this.#fountain.fragmentCount === 1 ? encodeUr(type, new Uint8Array(message)) : undefined;
  }

  get type(): UrType {
    return this.#type;
  }

  get fragmentCount(): number {
    return this.#fountain.fragmentCount;
  }

  get isSinglePart(): boolean {
    return this.#fountain.fragmentCount === 1;
  }

  get isComplete(): boolean {
    return this.#single === undefined ? this.#fountain.isComplete : this.#emitted;
  }

  /** Fragment indexes mixed into the most recently produced part. */
  get lastFragmentIndexes(): ReadonlyArray<number> {
    return this.#fountain.lastFragmentIndexes;
  }

  next(): IteratorResult<string, undefined> {
    const single = this.#single;
    if (single !== undefined) {
      this.#emitted = true;
      return { value: single, done: false };
    }
    const { value: part, done } = this.#fountain.next();
    if (done === true || part === undefined) {
      return { value: undefined, done: true };
    }
    const body = encodeBytewords(encodePart(part), "minimal");
    const uri = `ur:${this.#type}/${part.sequence}-${part.sequenceCount}/${body}`;
    return { value: uri, done: false };
  }

  [Symbol.iterator](): this {
    return this;
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
    const parsed = parseUr(text, this.#limits);
    this.#checkType(parsed.type);
    return parsed.kind === "single"
      ? this.#receiveSingle(parsed.type, parsed.message)
      : this.#receiveFountain(parsed.type, parsed.part);
  }

  /** Type admission: `accept` list (when non-empty), then the locked type. */
  #checkType(type: UrType): void {
    if (this.#accept.length > 0 && !this.#accept.some((t) => t === type)) {
      fail({ code: "UnexpectedType", expected: this.#accept, found: type });
    }
    const locked = this.#lockedType;
    if (locked !== undefined && locked !== type) {
      fail({ code: "UnexpectedType", expected: [locked], found: type });
    }
  }

  #receiveSingle(type: UrType, message: Uint8Array): ReceiveResult {
    // A single-part URI inside a collecting fountain session is inconsistent;
    // the reverse order is unreachable (a completed session is terminal).
    if (this.#fountain.state.phase !== "empty") {
      fail("InconsistentPart");
    }
    if (message.length > this.#limits.maxMessageLength) {
      return this.#fail({ code: "ResourceLimit", limit: "messageLength" });
    }
    this.#lockedType ??= type;
    this.#terminal = { phase: "complete", value: { type, message } };
    this.#processed += 1;
    return { status: "accepted" };
  }

  #receiveFountain(type: UrType, part: Part): ReceiveResult {
    const result = this.#fountain.receive(part);
    if (result.status === "rejected") {
      return result;
    }
    if (result.status === "fatal") {
      this.#terminal = { phase: "failed", error: result.error };
      return result;
    }
    this.#lockedType ??= type;
    this.#processed += 1;
    const fountainState = this.#fountain.state;
    if (fountainState.phase === "complete") {
      this.#terminal = {
        phase: "complete",
        value: { type, message: fountainState.value },
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
