# boundgap

Finds values whose validator guarantees a **weaker** bound than a later
consumer actually **requires** — the gap between two constants written in
different functions, often in different files, usually by different people
at different times.

```
handshake.cpp:201   if (m_iMSS < 32) return false;        // validator: >= 32
core.cpp:6003       m_iMaxSRTPayloadSize = m_iMSS - 44;    // consumer needs >= 44
```

Nothing is wrong at either line on its own. The bug only exists in the gap.
This is a real pattern from libsrt, and it's the case that motivated this
tool.

## Why not just use CodeQL / Semgrep / Cppcheck?

A 2026 formal-verification study of AI-generated C code ([arXiv
2604.05292](https://arxiv.org/pdf/2604.05292)) ran all three against ~68–90
confirmed C vulnerabilities of exactly this bounds-mismatch shape:

| Tool | Caught |
|---|---|
| CodeQL (security-extended) | 0 / 68 |
| Cppcheck | 0 / 80 |
| Clang Static Analyzer | 0 / 80 |
| Semgrep | 2 / 90 (by accident, via an unrelated rule) |

None of them look for "two constants that disagree," because that isn't a
taint-tracking problem or a pattern-match problem — it's a **cross-reference**
problem. A validator and its consumer can be hundreds of lines and several
files apart, connected only by a human-readable variable name. That's the gap
this tool sits in.

## What it is (and isn't)

boundgap is deliberately a **lead generator**, not a verifier. It reasons
about text, not semantics — no control-flow graph, no alias analysis, no
proof that a guard actually dominates a use. It correlates by normalized
identifier name across a codebase and flags where a validated lower bound is
smaller than what a later subtraction or array index demands.

Every hit is a hypothesis. Most large-codebase runs produce a mix of real
leads and name collisions (two unrelated variables that happen to both be
called `count`). To help you triage that, every hit is tagged by locality —
`same-file` hits (the identifier appears in both the guard and the consumer
in the same file) are far more likely to be real than `cross-file` ones, and
are sorted first.

## Usage

```bash
python3 boundgap.py /path/to/codebase
python3 boundgap.py /path/to/codebase --ext c,cc,cpp,h,hpp   # default
python3 boundgap.py /path/to/codebase --min-gap 4            # only gaps >= 4
python3 boundgap.py /path/to/codebase --json > findings.json # for CI/tooling
```

Try it on the bundled example first:

```bash
python3 boundgap.py examples/
```

```
=== [same-file] mss: validator guarantees >= 32, subtraction needs >= 44  (gap 12)
    guard    examples/handshake_example.cpp:13
             if (mss < 32) {          // validator: guarantees mss >= 32
    consumer examples/handshake_example.cpp:20
             int maxPayload = mss - 44;   // consumer: actually needs mss >= 44

1 candidate gap(s) (1 same-file, 0 same-dir, 0 cross-file)
```

## What it looks for

- **Validators**: `if (x < C) { reject }`, `if (x <= C) { reject }`, and
  `assert(x >= C)` / `assert(x > C)` — where `reject` is a `return`,
  `throw`, `goto err*`, or `abort()` within the next few lines.
- **Consumers**: `x - C` (subtraction) and `a[x - C]` (array indexing), where
  `C` is a resolvable integer literal, `#define`, or `const`/`constexpr`.
- `C` can be a named constant, a `#define`, or a small sum of either
  (`UDP_HDR_SIZE + HDR_SIZE`), resolved from the whole scanned tree before
  matching begins.

A second tier is also reported: cases where the validator is found but the
consumer's constant **couldn't** be resolved (a `sizeof`, a template
parameter, a cross-translation-unit enum). Silence on exactly this kind of
unresolved case is how the original libsrt bug slipped through review, so
it's surfaced rather than dropped.

## Known limitations

- Pure text/regex matching, no real parser. A guard and a consumer with the
  same normalized name in unrelated scopes will produce a `cross-file` hit —
  check locality and read the surrounding code before trusting anything.
- C/C++ only.
- Only two consumer shapes (subtraction, indexing). Multiplication/overflow,
  memcpy-length arguments, and upper-bound mismatches (a guard that caps a
  value *below* what a fixed buffer can hold) aren't covered yet — see the
  comment above `GUARD_GT` in the source for the reasoning on why that one
  was left unwired rather than shipped half-tested.

## License

MIT — see [LICENSE](LICENSE).
