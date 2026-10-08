import { readFileSync } from "node:fs";
import { join } from "node:path";

// Shared golden files live in the repository-root vectors/ tree; the Rust
// suite reads the same paths via crates/bcur/tests/ (see vectors/README.md).
const VECTORS = join(import.meta.dirname, "../../../vectors");

/** Raw vector file contents (UTF-8). */
export function vectorText(path: string): string {
  return readFileSync(join(VECTORS, path), "utf8");
}

/** Data-only line files: LF, trimmed, empty lines dropped. */
export function vectorLines(path: string): string[] {
  return vectorText(path)
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

/** JSON vector file parsed as T. */
// oxlint-disable-next-line no-unnecessary-type-parameters -- T names the spec shape at each call site
export function vectorJson<T>(path: string): T {
  const value: unknown = JSON.parse(vectorText(path));
  // oxlint-disable-next-line no-unsafe-type-assertion -- the caller names the shape each vector file declares
  return value as T;
}
