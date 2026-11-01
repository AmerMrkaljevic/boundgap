#!/usr/bin/env python3
"""boundgap — find values whose validator guarantees a weaker bound than a
later consumer requires.

The bug shape this looks for, in the words of the libsrt case that motivated it:

    handshake.cpp:201   if (m_iMSS < 32) return false;        // validator: >= 32
    core.cpp:6003       m_iMaxSRTPayloadSize = m_iMSS - 44;   // consumer needs >= 44

Nothing is wrong at either site on its own. The bug only exists in the gap
between two constants written in different functions, often in different files,
usually by different people at different times. Fuzzers miss these whenever the
resulting failure is caught, which is exactly what libsrt does.

This is deliberately a *lead generator*. It reasons about text, not semantics:
it does not know about control flow, aliasing, or whether a guard actually
dominates a use. Every hit is a hypothesis to be checked by hand.

Why not just use CodeQL / Semgrep / Cppcheck for this? A 2026 formal-verification
study of AI-generated C code (arxiv 2604.05292) ran all three against 68-90
confirmed C vulnerabilities of exactly this bounds-mismatch shape: CodeQL's
security-extended suite missed all of them (its overflow queries need an explicit
source-to-sink taint path, which a cross-function constant mismatch never forms),
Cppcheck and Clang Static Analyzer caught zero, and Semgrep caught 2/90 — by
accident, via an unrelated strcat rule. None of them look for "two constants
that disagree," because that is not a taint problem or a pattern-match problem,
it is a cross-reference problem. That is the gap this tool sits in.
"""
import re, sys, os, glob, argparse, json
from collections import defaultdict

# ---------------------------------------------------------------- constants
INT = r'(?:0[xX][0-9a-fA-F]+|\d+)'
# an identifier we are willing to track: members and locals, not literals
IDENT = r'[A-Za-z_][A-Za-z0-9_]*'

CONSTS = {}          # NAME -> int, harvested from the tree

def val(tok, depth=0):
    """Resolve a literal, a named constant, or a small sum of them."""
    tok = tok.strip()
    try:
        return int(tok, 0)
    except ValueError:
        pass
    if depth > 3:
        return None
    key = tok.split('::')[-1]
    if key in CONSTS:
        return CONSTS[key]
    if '+' in tok:                       # e.g. UDP_HDR_SIZE + HDR_SIZE
        parts = [val(x, depth + 1) for x in tok.split('+')]
        if all(p is not None for p in parts):
            return sum(parts)
    return None

def harvest_consts(paths):
    """#define N 44 / const int N = 44 / static const size_t N = 28; also
       simple sums, resolved in a second pass."""
    pend = {}
    dfn = re.compile(r'^\s*#\s*define\s+([A-Za-z_]\w*)\s+\(?([^/\n]+?)\)?\s*$')
    cst = re.compile(r'\b(?:static\s+)?(?:const|constexpr)\s+\w[\w:<>]*\s+([A-Za-z_]\w*)\s*=\s*([^;]+);')
    for path in paths:
        try:
            txt = open(path, encoding='utf-8', errors='replace').read()
        except OSError:
            continue
        for line in txt.splitlines():
            for rx in (dfn, cst):
                m = rx.search(line)
                if m:
                    pend[m.group(1)] = m.group(2).strip()
    for _ in range(4):                   # resolve chains like A = B + C
        for name, expr in list(pend.items()):
            if name in CONSTS:
                continue
            v = val(expr)
            if v is not None:
                CONSTS[name] = v
    return CONSTS

NOISE = {'i','j','k','n','x','y','len','size','count','idx','pos','end','ret','tmp'}

def norm(name):
    """m_config.iMSS, m_iMSS and mss all denote the same quantity to a human."""
    n = name.split('.')[-1].split('->')[-1]
    n = re.sub(r'^m_', '', n)
    n = re.sub(r'^[iufb](?=[A-Z])', '', n)   # Hungarian prefix
    n = n.lower()
    return None if n in NOISE or len(n) < 3 else n

# A guard is a comparison that leads to a rejection. We accept a rejection
# within a few lines, which is how these are written in practice. assert()
# is treated as its own unconditional guard below, since it is the common
# modern-C++ alternative to "if (!ok) return/throw" and was previously
# invisible to this tool entirely.
REJECT = re.compile(r'\b(return\s+(false|-1|0|NULL|nullptr)|return\s+\w*(REJECT|ERR|FAIL)\w*'
                    r'|throw\b|goto\s+\w*(err|fail|invalid)\w*|abort\(|reject)', re.I)

RHS   = rf'(?:{INT}|[A-Za-z_][\w:]*(?:\s*\+\s*[A-Za-z_][\w:]*)*)'
GUARD_LT = re.compile(rf'\b({IDENT})\s*<\s*({RHS})\b')      # x < C  -> reject means x >= C
GUARD_LE = re.compile(rf'\b({IDENT})\s*<=\s*({RHS})\b')     # x <= C -> reject means x >  C
# NOTE: GUARD_GT was defined in the original tool but never wired into
# scan() -- dead code. It establishes an UPPER bound (x > C, reject -> x <=
# C survives), which is a different shape than the lower[]/needs[] pipeline
# below: it would need its own consumer class (a fixed-size buffer
# declaration whose capacity is smaller than the guaranteed-but-weaker
# upper bound, e.g. `char buf[D]` fed from something only known to be <=
# C > D). That pattern needs real-codebase testing before it can be trusted
# not to be pure noise, so it is left unimplemented rather than shipped
# half-tested. Kept here (RHS instead of the old INT-only form, so a named
# constant like MAX_FOO is at least resolvable once this is wired up) as a
# documented next step, not a claimed fix.
GUARD_GT = re.compile(rf'\b({IDENT})\s*>\s*({RHS})\b')      # x > C  -> reject means x <= C (unused — see note)

# assert(x >= C) / assert(x > C): the assertion itself is the validator, no
# nearby "return false" to look for. Treated as its own guard family so the
# rest of the pipeline (lower[] bookkeeping) doesn't need to know the
# difference between "if+reject" and "assert" shaped guards.
ASSERT_GE = re.compile(rf'\bassert\s*\(\s*({IDENT})\s*>=\s*({RHS})\s*\)')
ASSERT_GT = re.compile(rf'\bassert\s*\(\s*({IDENT})\s*>\s*({RHS})\s*\)')

SUB   = re.compile(rf'\b({IDENT})\s*-\s*({RHS})\b')          # x - C   needs x >= C
DIV   = re.compile(rf'\b({IDENT})\s*/\s*({INT})\b')          # x / C   needs C != 0
INDEX = re.compile(rf'\[\s*({IDENT})\s*-\s*({RHS})\s*\]')    # a[x - C] needs x >= C

def scan(paths):
    # lower[name] -> [(bound, file, line, text)]
    lower = defaultdict(list)
    unresolved = defaultdict(list)
    needs = defaultdict(list)   # ident -> [(required, file, line, text, kind)]

    for path in paths:
        try:
            lines = open(path, encoding='utf-8', errors='replace').read().splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            s = line.strip()
            if s.startswith('//') or s.startswith('*') or s.startswith('#'):
                continue
            near = ' '.join(lines[i:i + 4])

            # --- validators: only count them when a rejection follows closely
            if REJECT.search(near):
                for m in GUARD_LT.finditer(s):
                    name, c = norm(m.group(1)), val(m.group(2))
                    if name is None: continue
                    if c is not None and c > 0:
                        lower[name].append((c, path, i + 1, s))
                for m in GUARD_LE.finditer(s):
                    name, c = norm(m.group(1)), val(m.group(2))
                    if name is None: continue
                    if c is not None and c > 0:
                        lower[name].append((c + 1, path, i + 1, s))

            # --- assert()-shaped validators: unconditional, no nearby reject
            # needed since the assert call itself is the enforcement.
            for m in ASSERT_GE.finditer(s):
                name, c = norm(m.group(1)), val(m.group(2))
                if name is not None and c is not None and c > 0:
                    lower[name].append((c, path, i + 1, s))
            for m in ASSERT_GT.finditer(s):
                name, c = norm(m.group(1)), val(m.group(2))
                if name is not None and c is not None and c > 0:
                    lower[name].append((c + 1, path, i + 1, s))

            # --- consumers: arithmetic that implies a stronger requirement
            for m in SUB.finditer(s):
                name, c = norm(m.group(1)), val(m.group(2))
                if name is None:
                    continue
                if c is not None and c > 1:
                    needs[name].append((c, path, i + 1, s, 'subtraction'))
                elif name is not None and c is None and not m.group(2).strip().isdigit():
                    # The constant could not be resolved (sizeof, a template
                    # parameter, a cross-TU enum). Silence here is how the
                    # motivating bug was missed, so surface it as second tier.
                    unresolved[name].append((path, i + 1, s, m.group(2).strip()))
            for m in INDEX.finditer(s):
                name, c = norm(m.group(1)), val(m.group(2))
                if name is None:
                    continue
                if c is not None and c > 0:
                    needs[name].append((c, path, i + 1, s, 'index'))
    return lower, needs, unresolved

def _locality(a_path, b_path):
    """Confidence tag for a (guard, consumer) pair. Same-file correlations
    are far more likely to be the same variable than a cross-codebase name
    match is -- the tool has no scoping/aliasing info, so this is the
    cheapest available signal for triage priority, and it matters: on a
    large tree, most of the raw hit list is cross-file name collisions
    (e.g. two unrelated 'count' guards), and those were previously mixed in
    with the real same-file leads with no way to tell them apart."""
    if a_path == b_path:
        return 'same-file'
    if os.path.dirname(a_path) == os.path.dirname(b_path):
        return 'same-dir'
    return 'cross-file'

def report(lower, needs, min_gap, as_json=False):
    hits = []
    for name, uses in needs.items():
        if name not in lower:
            continue                       # no validator found: too noisy to report
        best = max(b for b, *_ in lower[name])          # strongest guaranteed bound
        gsite = max(lower[name], key=lambda t: t[0])
        for required, path, line, text, kind in uses:
            if required > best and (required - best) >= min_gap:
                loc = _locality(gsite[1], path)
                hits.append((loc, required - best, name, best, gsite, required, path, line, text, kind))

    # same-file leads first (highest confidence), then by gap size within tier
    tier_rank = {'same-file': 0, 'same-dir': 1, 'cross-file': 2}
    hits.sort(key=lambda h: (tier_rank[h[0]], -h[1]))

    if as_json:
        out = [{
            'identifier': name, 'locality': loc, 'gap': gap,
            'guaranteed_min': best, 'required_min': required,
            'guard': {'file': gsite[1], 'line': gsite[2], 'text': gsite[3]},
            'consumer': {'file': path, 'line': line, 'text': text, 'kind': kind},
        } for loc, gap, name, best, gsite, required, path, line, text, kind in hits]
        print(json.dumps(out, indent=2))
        return hits

    for loc, gap, name, best, gsite, required, path, line, text, kind in hits:
        print(f"\n=== [{loc}] {name}: validator guarantees >= {best}, {kind} needs >= {required}  (gap {gap})")
        print(f"    guard    {gsite[1]}:{gsite[2]}")
        print(f"             {gsite[3][:110]}")
        print(f"    consumer {path}:{line}")
        print(f"             {text[:110]}")
    print(f"\n{len(hits)} candidate gap(s) "
          f"({sum(1 for h in hits if h[0]=='same-file')} same-file, "
          f"{sum(1 for h in hits if h[0]=='same-dir')} same-dir, "
          f"{sum(1 for h in hits if h[0]=='cross-file')} cross-file)")
    return hits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root')
    ap.add_argument('--ext', default='c,cc,cpp,h,hpp')
    ap.add_argument('--min-gap', type=int, default=1)
    ap.add_argument('--json', action='store_true', help='emit JSON instead of text (for CI)')
    a = ap.parse_args()

    paths = []
    for e in a.ext.split(','):
        paths += glob.glob(os.path.join(a.root, '**', f'*.{e}'), recursive=True)
    paths = [p for p in paths if '/test' not in p and '/build' not in p]
    print(f"scanning {len(paths)} files under {a.root}", file=sys.stderr)

    harvest_consts(paths)
    print(f"resolved {len(CONSTS)} named constants", file=sys.stderr)
    lower, needs, unresolved = scan(paths)
    report(lower, needs, a.min_gap, as_json=a.json)

    if a.json:
        return  # second-tier text report doesn't make sense mixed into JSON output

    print("\n--- second tier: guarded value, consumer constant not resolvable ---")
    n = 0
    for name, uses in sorted(unresolved.items()):
        if name not in lower:
            continue
        best = max(b for b, *_ in lower[name])
        gs = max(lower[name], key=lambda t: t[0])
        for path, line, text, expr in uses[:3]:
            print(f"  {name}: guard >= {best} at {gs[1]}:{gs[2]}")
            print(f"     consumer {path}:{line}  (constant '{expr}' unresolved)")
            print(f"     {text[:110]}")
            n += 1
    print(f"  {n} second-tier lead(s)")

if __name__ == '__main__':
    main()
