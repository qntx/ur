import { fail } from "../error.ts";
import { fromUr, tagUrTypes, Ur } from "../typed/index.ts";
import type { UrCodec, UrType } from "../typed/index.ts";

export function codecMap(
  codecs: ReadonlyArray<UrCodec<unknown>>,
): ReadonlyMap<UrType, UrCodec<unknown>> {
  const m = new Map<UrType, UrCodec<unknown>>();
  for (const c of codecs) {
    for (const t of tagUrTypes(c.tags)) {
      if (m.has(t)) {
        throw new TypeError(`duplicate codec for UR type ${t}`);
      }
      m.set(t, c);
    }
  }
  return m;
}

export function fromUrStringWith(
  uri: string,
  codecs: ReadonlyMap<UrType, UrCodec<unknown>>,
): { readonly type: UrType; readonly value: unknown } {
  const ur = Ur.parse(uri);
  const codec = codecs.get(ur.type);
  if (codec === undefined) {
    fail({
      code: "UnexpectedType",
      expected: [...codecs.keys()],
      found: ur.type,
    });
  }
  return { type: ur.type, value: fromUr(ur, codec) };
}
