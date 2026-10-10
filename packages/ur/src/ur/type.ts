import { asciiLower } from "../ascii.ts";
import { fail } from "../error.ts";

declare const urTypeBrand: unique symbol;

/** Validated UR type token: canonical lowercase `[a-z0-9-]+`. */
export type UrType = string & { readonly [urTypeBrand]: true };

/** Validate and lowercase a UR type token. Throws `UrError(InvalidType)`. */
export function parseUrType(text: string): UrType {
  const lower = asciiLower(text);
  if (lower.length === 0 || !/^[a-z0-9-]+$/.test(lower)) {
    fail("InvalidType");
  }
  return lower as UrType; // oxlint-disable-line typescript/no-unsafe-type-assertion -- the brand is exactly this validation
}

/** True iff `text` is already a canonical lowercase UR type token (no folding). */
export function isUrType(text: string): text is UrType {
  return /^[a-z0-9-]+$/.test(text);
}
