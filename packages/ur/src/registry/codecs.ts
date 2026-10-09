import { fail } from "../error.ts";
import { fromUr, tagUrTypes, Ur } from "../typed/index.ts";
import type { UrCodec } from "../typed/index.ts";
import { UrType } from "../ur/index.ts";

export function codecMap(
  codecs: ReadonlyArray<UrCodec<unknown>>,
): ReadonlyMap<string, UrCodec<unknown>> {
  const m = new Map<string, UrCodec<unknown>>();
  for (const c of codecs) {
    for (const t of tagUrTypes(c.tags)) {
      if (m.has(t.value)) {
        throw new TypeError(`duplicate codec for UR type ${t.value}`);
      }
      m.set(t.value, c);
    }
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
    fail({
      code: "UnexpectedType",
      expected: [...codecs.keys()].map((t) => UrType.parse(t)),
      found: ur.type,
    });
  }
  return { type: ur.type.value, value: fromUr(ur, codec) };
}
