/**
 * Anchored text-extraction helpers shared by scripts/vectors/extract-official.ts and its unit
 * tests. Every helper throws via `fail` when its anchor is missing so the extractor never emits a
 * silent partial vector.
 */

export function fail(message: string): never {
  throw new Error(`extract-official: ${message}`);
}

export function expect(condition: boolean, message: string): asserts condition {
  if (!condition) {
    fail(message);
  }
}

/** `value` when defined, otherwise fail — the extraction counterpart of a non-null assertion. */
export function req<T>(value: T | undefined, label: string): T {
  expect(value !== undefined, label);
  return value;
}

/** Balanced `{…}` / `[…]` / `(…)` slice starting at `open`. */
export function balanced(text: string, open: number): string {
  const pairs: Record<string, string> = { "{": "}", "[": "]", "(": ")" };
  const openCh = text[open];
  const closeCh = openCh === undefined ? undefined : pairs[openCh];
  expect(openCh !== undefined && closeCh !== undefined, `balanced: no bracket at offset ${open}`);
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === openCh) {
      depth += 1;
    } else if (ch === closeCh) {
      depth -= 1;
      if (depth === 0) {
        return text.slice(open, i + 1);
      }
    }
  }
  return fail(`balanced: unclosed '${openCh}' at offset ${open}`);
}

/**
 * Body slice of a Swift `func name(…) {` or C/C++ `name(…) {` function, located by `marker` (a
 * unique substring such as `"func testRNG1"` or `"void test_rng_1"`).
 */
export function funcBody(text: string, marker: string): string {
  const start = text.indexOf(marker);
  expect(start !== -1, `missing function marker '${marker}'`);
  const open = text.indexOf("{", start);
  expect(open !== -1, `missing '{' after '${marker}'`);
  return balanced(text, open);
}

/** Fenced ```lang blocks in a Markdown document (`lang` "" selects untagged fences). */
export function codeBlocks(markdown: string, lang: string): string[] {
  const blocks: string[] = [];
  const re = /```([^\n]*)\n([\s\S]*?)```/g;
  for (const m of markdown.matchAll(re)) {
    const [, tag, body] = m;
    if (tag === lang && body !== undefined) {
      blocks.push(body);
    }
  }
  return blocks;
}

/** The fenced `…` block whose body contains `needle`. */
export function codeBlockContaining(markdown: string, needle: string): string {
  const block = codeBlocks(markdown, "").find((b) => b.includes(needle));
  expect(block !== undefined, `no fenced code block contains '${needle}'`);
  return block;
}

/** The first fenced `…` block that begins after `marker` (e.g. a prose label). */
export function codeBlockAfter(markdown: string, marker: string): string {
  const i = markdown.indexOf(marker);
  expect(i !== -1, `missing marker '${marker}'`);
  const open = markdown.indexOf("```", i + marker.length);
  expect(open !== -1, `no fenced block after '${marker}'`);
  const start = markdown.indexOf("\n", open) + 1;
  const close = markdown.indexOf("```", start);
  expect(close !== -1, `unclosed fenced block after '${marker}'`);
  return markdown.slice(start, close);
}

/** Swift `func` body inside a fenced code block of a Markdown doc. */
export function docFuncBody(markdown: string, name: string): string {
  for (const block of codeBlocks(markdown, "swift")) {
    if (block.includes(`func ${name}`)) {
      return funcBody(block, `func ${name}`);
    }
  }
  return fail(`doc: no swift code block defines '${name}'`);
}

/** First `{`/`[` bracketed block that follows `marker`. */
export function bracketBlock(text: string, marker: string): string {
  const m = text.indexOf(marker);
  expect(m !== -1, `missing marker '${marker}'`);
  const square = text.indexOf("[", m);
  const curly = text.indexOf("{", m);
  if (square !== -1 && (curly === -1 || square < curly)) {
    return balanced(text, square);
  }
  expect(curly !== -1, `missing '[' or '{' after '${marker}'`);
  return balanced(text, curly);
}

/** Integer literals (`1_005`, `0x1f`, plain digits) inside `text`. */
export function numbers(text: string): number[] {
  const out: number[] = [];
  for (const m of text.matchAll(/0x[0-9a-fA-F]+|\d[\d_]*/g)) {
    const [t] = m;
    out.push(t.startsWith("0x") ? Number.parseInt(t, 16) : Number(t.replaceAll("_", "")));
  }
  return out;
}

/** Flat number list inside the first bracket block after `marker`. */
export function intList(text: string, marker: string): number[] {
  return numbers(bracketBlock(text, marker));
}

/** Nested number lists inside the first bracket block after `marker`. */
export function intMatrix(text: string, marker: string): number[][] {
  const block = bracketBlock(text, marker);
  const inner = block.slice(1, -1);
  const rows: number[][] = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < inner.length; i += 1) {
    const ch = inner[i];
    if (ch === "[" || ch === "{") {
      if (depth === 0) {
        start = i;
      }
      depth += 1;
    } else if (ch === "]" || ch === "}") {
      depth -= 1;
      if (depth === 0 && start >= 0) {
        rows.push(numbers(inner.slice(start, i + 1)));
      }
    }
  }
  return rows;
}

/** `"…"` string literals inside `text` (skips `"""` multiline delimiters). */
export function stringLiterals(text: string): string[] {
  const out: string[] = [];
  const re = /"((?:[^"\\\n]|\\.)*)"/g;
  for (const m of text.matchAll(re)) {
    const [, value] = m;
    if (value !== undefined) {
      out.push(value);
    }
  }
  return out;
}

/** String literals inside the first bracket block after `marker`. */
export function stringList(text: string, marker: string): string[] {
  return stringLiterals(bracketBlock(text, marker));
}

/**
 * Adjacent-literal concatenation `name = "a" "b" "c";` joined into one string (C++ / Swift
 * continued-line literals). Reads from `marker` to the next `;`.
 */
export function concatString(text: string, marker: string): string {
  const i = text.indexOf(marker);
  expect(i !== -1, `missing marker '${marker}'`);
  const end = text.indexOf(";", i);
  expect(end !== -1, `missing ';' after '${marker}'`);
  return stringLiterals(text.slice(i, end)).join("");
}

/** Swift `"""…"""` multiline string content after `marker`, whitespace-normalized to one line. */
export function multilineString(text: string, marker: string): string {
  const i = text.indexOf(marker);
  expect(i !== -1, `missing marker '${marker}'`);
  const open = text.indexOf('"""', i);
  expect(open !== -1, `missing '"""' after '${marker}'`);
  const close = text.indexOf('"""', open + 3);
  expect(close !== -1, `unclosed '"""' after '${marker}'`);
  return text
    .slice(open + 3, close)
    .replaceAll(/\\\n\s*/g, "")
    .replaceAll(/\s+/g, " ")
    .trim();
}

/** `ur:type/…` literals inside `text`. */
export function urLiterals(text: string): string[] {
  return [...text.matchAll(/ur:[a-z0-9-]+\/[^"\s,)']+/g)].map((m) => m[0]);
}

/** First long (≥8 hex chars) hex literal inside `text`, lowercased. */
export function hexLiteral(text: string, marker?: string): string {
  let slice = text;
  if (marker !== undefined) {
    const i = text.indexOf(marker);
    expect(i !== -1, `missing marker '${marker}'`);
    slice = text.slice(i);
  }
  const m = /"?([0-9a-fA-F]{8,})"?/.exec(slice);
  expect(m !== null && m[1] !== undefined, "no hex literal found");
  return m[1].toLowerCase();
}
