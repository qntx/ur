import { fail } from "../error.ts";
import { firstTagUrType, fromUr, Ur } from "../typed/index.ts";
import type { UrCodec } from "../typed/index.ts";

export function codecMap(
  codecs: ReadonlyArray<UrCodec<unknown>>,
): ReadonlyMap<string, UrCodec<unknown>> {
  const m = new Map<string, UrCodec<unknown>>();
  for (const c of codecs) {
    const token = firstTagUrType(c.tags).value;
    if (m.has(token)) {
      throw new TypeError(`duplicate codec for UR type ${token}`);
    }
    m.set(token, c);
  }
  return m;
}

export function fromUrStringWith(
  uri: string,
  codecs: ReadonlyMap<string, UrCodec<unknown>>,
): { readonly type: string; readonly value: unknown } {
  const ur = Ur.fromUrString(uri);
  const codec = codecs.get(ur.type.value);
  if (codec === undefined) {
    fail("UnexpectedType", {
      expected: [...codecs.keys()].join("|"),
      found: ur.type.value,
    });
  }
  return { type: ur.type.value, value: fromUr(ur, codec) };
}
