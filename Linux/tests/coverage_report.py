#!/usr/bin/env python3
"""Merges gcov data from several instrumented runs (end-to-end suites, unit tests) into one line-coverage table.

usage: coverage_report.py [--uncovered FILE] [--min-library PCT] DIR [DIR...]
Every *.gcda below the given directories is read with `gcov --json-format`; a line counts as covered when any run executed it.
"""
import json, os, subprocess, sys

def main():
    args = sys.argv[1:]
    uncovered_out = min_lib = None
    while args and args[0].startswith("--"):
        if args[0] == "--uncovered": uncovered_out = args[1]; args = args[2:]
        elif args[0] == "--min-library": min_lib = float(args[1]); args = args[2:]
        else: sys.exit("unknown option " + args[0])
    if not args: sys.exit(__doc__)

    root = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    wanted = [os.path.join(root, d) + os.sep for d in ("src", "cli", "gui", "profile")]
    lines = {}          # path -> {line: covered}
    funcs = {}          # path -> {name: executed}
    for top in args:
        for dirpath, _, names in os.walk(top):
            for n in names:
                if not n.endswith(".gcda"): continue
                gcda = os.path.join(dirpath, n)
                p = subprocess.run(["gcov", "--json-format", "--stdout", "-o", dirpath, gcda], capture_output=True, text=True)
                if p.returncode != 0 or not p.stdout.strip(): continue
                for doc in p.stdout.splitlines():
                    if not doc.startswith("{"): continue
                    d = json.loads(doc)
                    cwd = d.get("current_working_directory", "")
                    for f in d["files"]:
                        path = os.path.realpath(os.path.join(cwd, f["file"]))
                        if not any(path.startswith(w) for w in wanted) or "/tests/" in path or path.endswith(".skel.h"): continue
                        L = lines.setdefault(path, {})
                        for ln in f["lines"]:
                            L[ln["line_number"]] = L.get(ln["line_number"], False) or ln["count"] > 0
                        F = funcs.setdefault(path, {})
                        for fn in f["functions"]:
                            F[fn["name"]] = F.get(fn["name"], False) or fn["execution_count"] > 0

    rows, tot, cov, ltot, lcov = [], 0, 0, 0, 0
    missing = []
    for path in sorted(lines):
        L = lines[path]
        n, c = len(L), sum(1 for v in L.values() if v)
        rel = os.path.relpath(path, root)
        fn_n, fn_c = len(funcs[path]), sum(1 for v in funcs[path].values() if v)
        rows.append((rel, n, c, fn_n, fn_c))
        tot += n; cov += c
        if rel.startswith(("src/", "profile/")): ltot += n; lcov += c
        miss = sorted(k for k, v in L.items() if not v)
        if miss: missing.append((rel, miss))
    print("%-28s %8s %8s %7s %12s" % ("file", "lines", "covered", "%", "functions"))
    for rel, n, c, fn_n, fn_c in rows:
        print("%-28s %8d %8d %6.1f%% %7d/%-4d" % (rel, n, c, 100.0 * c / n if n else 100, fn_c, fn_n))
    print("%-28s %8d %8d %6.1f%%" % ("TOTAL", tot, cov, 100.0 * cov / tot if tot else 0))
    lib = 100.0 * lcov / ltot if ltot else 0
    print("%-28s %8d %8d %6.1f%%   (library + profile reader)" % ("LIBRARY", ltot, lcov, lib))

    if uncovered_out:
        with open(uncovered_out, "w") as out:
            for rel, miss in missing:
                ranges, start, prev = [], None, None
                for k in miss + [None]:
                    if start is None: start = prev = k
                    elif k is not None and k == prev + 1: prev = k
                    else:
                        ranges.append(str(start) if start == prev else "%d-%d" % (start, prev)); start = prev = k
                out.write("%s: %s\n" % (rel, ", ".join(ranges)))
    if min_lib is not None and lib < min_lib:
        print("library coverage %.1f%% is below the required %.1f%%" % (lib, min_lib)); sys.exit(1)

main()
