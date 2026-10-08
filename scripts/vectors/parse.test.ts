import { expect, test } from "vite-plus/test";

import {
  balanced,
  codeBlockContaining,
  codeBlocks,
  concatString,
  docFuncBody,
  funcBody,
  hexLiteral,
  intList,
  intMatrix,
  multilineString,
  stringList,
  urLiterals,
} from "./parse.ts";

const SWIFT = `
func testRNG1() {
    let rng = Xoshiro256(string: "Wolf")
    let numbers = (0 ..< 100).map { _ in Int(rng.next() % 100) }
    let expectedNumbers = [42, 81, 85]
    XCTAssertEqual(numbers, expectedNumbers)
}

func testChooser() {
    let expected = [
        [0],
        [1, 5],
    ]
}
`;

const CPP = `
static void test_shuffle() {
    vector<int> values = {1, 2, 3};
    vector<vector<int>> expected = {
        {6, 4},
        {10, 8}
    };
    string encoded =
        "able acid "
        "also lava";
    assert(true);
}
`;

const MD = "# Doc\n\n```swift\nfunc testA() {\n    let x = 1\n}\n```\n\n```\nur:seed/oyad\n```\n";

test("funcBody returns a brace-balanced slice", () => {
  const body = funcBody(SWIFT, "func testRNG1");
  expect(body.startsWith("{")).toBe(true);
  expect(body.endsWith("}")).toBe(true);
  expect(body).toContain("expectedNumbers");
  expect(body).not.toContain("testChooser");
});

test("intList parses bracketed number lists", () => {
  expect(intList(SWIFT, "expectedNumbers")).toStrictEqual([42, 81, 85]);
});

test("intMatrix parses nested number lists in swift and C++ syntax", () => {
  expect(intMatrix(SWIFT, "let expected =")).toStrictEqual([[0], [1, 5]]);
  expect(intMatrix(CPP, "expected =")).toStrictEqual([
    [6, 4],
    [10, 8],
  ]);
});

test("concatString joins adjacent C++ string literals", () => {
  expect(concatString(CPP, "string encoded")).toBe("able acid also lava");
});

test("stringList collects literals inside a bracket block", () => {
  const src = `let parts = ["a1", "b2"]`;
  expect(stringList(src, "let parts")).toStrictEqual(["a1", "b2"]);
});

test("multilineString normalizes swift triple-quoted strings", () => {
  const src = `let s = """\nyank toys \\\nopen brag\n"""`;
  expect(multilineString(src, "let s")).toBe("yank toys open brag");
});

test("codeBlocks and codeBlockContaining select fenced blocks", () => {
  expect(codeBlocks(MD, "swift")).toHaveLength(1);
  expect(codeBlockContaining(MD, "ur:seed")).toContain("ur:seed/oyad");
});

test("docFuncBody finds a function inside a doc code block", () => {
  expect(docFuncBody(MD, "testA")).toContain("let x = 1");
});

test("hexLiteral lowercases long hex runs", () => {
  expect(hexLiteral(`hex: "A20150C7098580"`)).toBe("a20150c7098580");
});

test("urLiterals extracts ur: strings", () => {
  expect(urLiterals(`assert(x == "ur:bytes/hdeymejt")`)).toStrictEqual(["ur:bytes/hdeymejt"]);
});

test("balanced throws on unclosed input", () => {
  expect(() => balanced("{ a", 0)).toThrow(/unclosed/);
});
