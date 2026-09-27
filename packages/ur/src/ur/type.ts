import { fail } from "../error.ts";

/** Validated UR type token (stored lowercase, `[a-z0-9-]+`). */
export class UrType {
  readonly value: string;

  private constructor(value: string) {
    this.value = value;
  }

  static parse(s: string): UrType {
    const lower = s.toLowerCase();
    if (lower.length === 0 || !/^[a-z0-9-]+$/.test(lower)) {
      fail("InvalidType");
    }
    return new UrType(lower);
  }

  static bytes(): UrType {
    return new UrType("bytes");
  }

  equals(other: UrType): boolean {
    return this.value === other.value;
  }
}
