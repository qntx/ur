/**
 * ASCII-only character helpers. `String.prototype.toLowerCase`/`toUpperCase` are Unicode-aware
 * (e.g. `"\u212A"` folds to `"k"`); the UR wire format folds ASCII letters only, like Rust
 * `to_ascii_lowercase`/`to_ascii_uppercase`.
 */

/** True iff every code point of `text` is `<= 0x7F`. */
export function isAscii(text: string): boolean {
  for (const ch of text) {
    if ((ch.codePointAt(0) ?? 0) > 0x7f) {
      return false;
    }
  }
  return true;
}

/** Lowercase ASCII `A-Z` only; every other code unit is left untouched. */
export function asciiLower(text: string): string {
  return text.replaceAll(/[A-Z]/g, (ch) => String.fromCodePoint((ch.codePointAt(0) ?? 0) + 0x20));
}

/** Uppercase ASCII `a-z` only; every other code unit is left untouched. */
export function asciiUpper(text: string): string {
  return text.replaceAll(/[a-z]/g, (ch) => String.fromCodePoint((ch.codePointAt(0) ?? 0) - 0x20));
}
