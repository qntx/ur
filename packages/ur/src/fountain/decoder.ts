import { FragmentChooser } from "../consensus/chooser.ts";
import { checksum } from "../consensus/crc32.ts";
import { UrError, fail } from "../error.ts";
import type { UrErrorInfo, UrLimit } from "../error.ts";
import { mergeLimits } from "./limits.ts";
import type { DecoderLimits } from "./limits.ts";
import type { Part } from "./part.ts";
import { validatePart } from "./part.ts";

function keyOf(indexes: number[]): string {
  return indexes.join(",");
}

function xorInto(target: Uint8Array, src: Uint8Array): void {
  if (target.length !== src.length) {
    fail("Internal");
  }
  for (const [i, a] of target.entries()) {
    const b = src[i];
    if (b === undefined) {
      fail("Internal");
    }
    target[i] = a ^ b;
  }
}

/** Fountain decoder with resource limits and fail-closed poison. */
export class FountainDecoder {
  private readonly decoded = new Map<number, Part>();
  private readonly received = new Set<string>();
  private readonly buffer = new Map<string, { indexes: number[]; part: Part }>();
  private readonly bufferIndex = new Map<number, Set<string>>();
  private readonly queue: Array<{ index: number; part: Part }> = [];
  private sequenceCount = 0;
  private messageLength = 0;
  private messageChecksum = 0;
  private fragmentLength = 0;
  private readonly limits: DecoderLimits;
  private chooser: FragmentChooser | undefined;
  private poisoned: UrErrorInfo | undefined;

  constructor(limits?: Partial<DecoderLimits>) {
    this.limits = mergeLimits(limits);
  }

  get maxFragmentDataLength(): number {
    return this.limits.maxFragmentDataLength;
  }

  get maxFragmentCount(): number {
    return this.limits.maxFragmentCount;
  }

  get isPoisoned(): boolean {
    return this.poisoned !== undefined;
  }

  get poisonState(): UrErrorInfo | undefined {
    return this.poisoned;
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

  /**
   * Receive a fountain part.
   *
   * @returns Whether the part was newly ingested.
   */
  receive(part: Part): boolean {
    if (this.poisoned) {
      throw new UrError(this.poisoned);
    }
    if (this.complete) {
      return false;
    }

    validatePart(part);
    if (part.data.length > this.limits.maxFragmentDataLength) {
      this.poisonLimit("fragmentLength");
    }

    if (this.received.size === 0) {
      const sc = part.sequenceCount;
      const ml = part.messageLength;
      if (sc > this.limits.maxFragmentCount) {
        this.poisonLimit("fragmentCount");
      }
      if (ml > this.limits.maxMessageLength) {
        this.poisonLimit("messageLength");
      }
      this.sequenceCount = sc;
      this.messageLength = ml;
      this.messageChecksum = part.checksum;
      this.fragmentLength = part.data.length;
      this.chooser = new FragmentChooser(sc, part.checksum);
    } else if (!this.validate(part)) {
      fail("InconsistentPart");
    }

    const { chooser } = this;
    if (chooser === undefined) {
      fail("Internal");
    }
    const indexes = chooser.choose(part.sequence);
    const key = keyOf(indexes);
    if (this.received.has(key)) {
      return false;
    }
    if (this.received.size >= this.limits.maxReceivedParts) {
      this.poisonLimit("receivedParts");
    }
    this.received.add(key);

    try {
      if (indexes.length === 1) {
        this.enqueueSimple(part, indexes);
      } else {
        this.processComplex(part, indexes);
      }
      this.processQueue();
    } catch (error) {
      this.escalate(error);
    }
    return true;
  }

  private enqueueSimple(part: Part, indexes: number[]): void {
    const [index] = indexes;
    if (index === undefined) {
      fail("Internal");
    }
    if (this.decoded.has(index)) {
      return;
    }
    this.decoded.set(index, part);
    this.queue.push({ index, part });
  }

  private processQueue(): void {
    while (this.queue.length > 0) {
      const item = this.queue.pop();
      if (item === undefined) {
        fail("Internal");
      }
      const { index, part: simple } = item;
      const toProcess = this.bufferIndex.get(index);
      if (toProcess === undefined) {
        continue;
      }
      for (const k of toProcess) {
        this.reduceBufferedPart(k, index, simple);
      }
    }
  }

  private reduceBufferedPart(key: string, knownIndex: number, simple: Part): void {
    const entry = this.buffer.get(key);
    if (!entry) {
      fail("Internal");
    }
    this.buffer.delete(key);
    for (const idx of entry.indexes) {
      const keys = this.bufferIndex.get(idx);
      if (keys === undefined) {
        fail("Internal");
      }
      keys.delete(key);
      if (keys.size === 0) {
        this.bufferIndex.delete(idx);
      }
    }
    const newIndexes = entry.indexes.filter((x) => x !== knownIndex);
    if (newIndexes.length === entry.indexes.length) {
      fail("Internal");
    }
    const data = new Uint8Array(entry.part.data);
    xorInto(data, simple.data);
    const reduced: Part = {
      sequence: entry.part.sequence,
      sequenceCount: entry.part.sequenceCount,
      messageLength: entry.part.messageLength,
      checksum: entry.part.checksum,
      data,
    };
    this.insertReduced(newIndexes, reduced);
  }

  private processComplex(part: Part, indexes: number[]): void {
    const remaining: number[] = [];
    const data = new Uint8Array(part.data);
    for (const idx of indexes) {
      const decoded = this.decoded.get(idx);
      if (decoded === undefined) {
        remaining.push(idx);
      } else {
        xorInto(data, decoded.data);
      }
    }
    if (remaining.length === 0) {
      return;
    }
    const reduced: Part = {
      sequence: part.sequence,
      sequenceCount: part.sequenceCount,
      messageLength: part.messageLength,
      checksum: part.checksum,
      data,
    };
    this.insertReduced(remaining, reduced);
  }

  private insertReduced(indexes: number[], part: Part): void {
    if (indexes.length === 1) {
      const [idx] = indexes;
      if (idx === undefined) {
        fail("Internal");
      }
      if (this.decoded.has(idx)) {
        return;
      }
      this.decoded.set(idx, part);
      this.queue.push({ index: idx, part });
      return;
    }
    const key = keyOf(indexes);
    if (!this.buffer.has(key) && this.buffer.size >= this.limits.maxBufferParts) {
      this.poisonLimit("bufferParts");
    }
    this.buffer.set(key, { indexes, part });
    for (const idx of indexes) {
      let keys = this.bufferIndex.get(idx);
      if (keys === undefined) {
        keys = new Set();
        this.bufferIndex.set(idx, keys);
      }
      keys.add(key);
    }
  }

  get complete(): boolean {
    return this.messageLength !== 0 && this.decoded.size === this.sequenceCount;
  }

  resolvedFragmentCount(): number | undefined {
    return this.messageLength === 0 ? undefined : this.decoded.size;
  }

  get fragmentCount(): number {
    return this.sequenceCount;
  }

  validate(part: Part): boolean {
    if (this.received.size === 0) {
      return false;
    }
    return (
      part.sequenceCount === this.sequenceCount &&
      part.messageLength === this.messageLength &&
      part.checksum === this.messageChecksum &&
      part.data.length === this.fragmentLength
    );
  }

  /** Decoded message if complete; otherwise `undefined`. */
  message(): Uint8Array | undefined {
    if (this.poisoned) {
      throw new UrError(this.poisoned);
    }
    if (!this.complete) {
      return undefined;
    }
    const combined = new Uint8Array(this.fragmentLength * this.sequenceCount);
    for (let idx = 0; idx < this.sequenceCount; idx++) {
      const part = this.decoded.get(idx);
      if (!part) {
        fail("Internal");
      }
      combined.set(part.data, idx * this.fragmentLength);
    }
    for (let i = this.messageLength; i < combined.length; i++) {
      if (combined[i] !== 0) {
        fail("InvalidPadding");
      }
    }
    const message = combined.subarray(0, this.messageLength);
    if (checksum(message) !== this.messageChecksum) {
      fail("InvalidMessageChecksum");
    }
    return new Uint8Array(message);
  }
}
