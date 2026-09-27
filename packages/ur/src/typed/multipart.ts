import { encodeCbor } from "@blockchaincommons/dcbor";

import { fail, failPoison } from "../error.ts";
import type { DecoderPoison } from "../error.ts";
import type { DecoderLimits } from "../fountain/index.ts";
import type { UrType } from "../ur/index.ts";
import { Decoder, Encoder } from "../ur/index.ts";
import { Ur, mapCborType } from "./ur.ts";

export class MultipartEncoder {
  readonly #inner: Encoder;

  private constructor(inner: Encoder) {
    this.#inner = inner;
  }

  static create(ur: Ur, maxFragmentLength: number): MultipartEncoder {
    const bytes = mapCborType(() => encodeCbor(ur.cbor));
    return new MultipartEncoder(Encoder.create(bytes, maxFragmentLength, ur.type));
  }

  nextPart(): string {
    return this.#inner.nextPart();
  }

  get isSinglePart(): boolean {
    return this.#inner.isSinglePart;
  }

  get fragmentCount(): number {
    return this.#inner.fragmentCount;
  }

  get currentIndex(): number {
    return this.#inner.currentIndex;
  }

  get complete(): boolean {
    return this.#inner.complete;
  }
}

export class MultipartDecoder {
  readonly #inner: Decoder;

  constructor(options?: { limits?: Partial<DecoderLimits>; expectedType?: UrType }) {
    this.#inner = new Decoder(options);
  }

  receive(uri: string): void {
    this.#inner.receive(uri);
  }

  get complete(): boolean {
    return this.#inner.complete;
  }

  get fragmentCount(): number {
    return this.#inner.fragmentCount;
  }

  resolvedFragmentCount(): number | undefined {
    return this.#inner.resolvedFragmentCount();
  }

  get type(): UrType | undefined {
    return this.#inner.type;
  }

  get isPoisoned(): boolean {
    return this.#inner.isPoisoned;
  }

  get poisonState(): DecoderPoison | undefined {
    return this.#inner.poisonState;
  }

  message(): Ur | undefined {
    if (this.#inner.isPoisoned) {
      const poison = this.#inner.poisonState;
      if (poison === undefined) {
        fail("DecoderState");
      }
      failPoison(poison);
    }
    const data = this.#inner.message();
    if (data === undefined) {
      return undefined;
    }
    const { type } = this.#inner;
    if (type === undefined) {
      fail("DecoderState");
    }
    return Ur.fromCborData(type, data);
  }
}
