#!/usr/bin/env python3
"""govulncheck's module scan over the regtest tool modules, minus what is accepted.

`make vuln`'s `govulncheck ./...` covers the root module. regtest/tools/nwctool
and regtest/tools/zaptool are SEPARATE modules the gate never scanned, and their
x/crypto and x/sys drifted into three advisories (GO-2026-6354 and 6355 in
x/crypto, GO-2026-5024 in x/sys) that the repository first heard about from a
public OpenSSF Scorecard score (0vk.58). This closes MOST of that (zu5.12): the
module scan finds the x/crypto pair, but not 5024 — govulncheck never lists it
for zaptool at x/sys v0.31.0, on any GOOS, because no x/sys package is built
there. Scorecard's OSV version query remains the only thing that sees that shape.

    python3 scripts/vuln_tools.py <govulncheck> -scan module -format json

Everything after the script name is the govulncheck command, run bare in each
module directory: the Makefile states the flags so they are visible in `make -n
vuln`, where internal/arch asserts them. `-scan module` takes no package pattern.

WHY NOT GOVULNCHECK'S EXIT CODE. The text format exits 3 on any finding, and
nwctool carries GO-2026-5932 permanently, so that exit is red forever with nothing
to fix. `-format json` exits 0 WHATEVER it finds. So the verdict is a set
difference against regtest/tools/vuln-accepted.txt, both ways:

    found - accepted   red: a new advisory, named with its module
    accepted - found   red: a stale acceptance, which bounds nothing

EXITS, and they are not interchangeable:

    0  every module scanned; every finding accepted; every acceptance found
    1  a finding: a new advisory, a stale or malformed acceptance
    2  COULD NOT CHECK: govulncheck did not run, exited non-zero (no database,
       bad flag, no toolchain), or its output was not a module scan. Never green,
       and never read as "no findings" — silence has to mean passed.

Modules are found as internal/arch's TestTheRegtestToolModulesTrackTheRootGo finds
them, `regtest/tools/*/go.mod`, so a new tool module is scanned the day it
appears. guardctl and mactool are in the root module, which `./...` covers.
"""

import glob
import json
import os
import subprocess
import sys

ACCEPTED = "regtest/tools/vuln-accepted.txt"
MODULES = "regtest/tools/*/go.mod"


class CannotCheck(Exception):
    pass


def accepted():
    """{(module dir, ID): reason}, refusing an entry without a reason."""
    entries, problems = {}, []
    try:
        f = open(ACCEPTED)
    except FileNotFoundError:
        raise CannotCheck(ACCEPTED + " is missing")
    with f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 2)
            if len(parts) < 3:
                problems.append("%s:%d: needs <module directory> <advisory> <reason>; "
                                "an acceptance without its reason is refused" % (ACCEPTED, n))
                continue
            # Spelled as the glob spells it, so `regtest/tools/a/` is not a second
            # module that "does not exist" beside the finding it was meant to accept.
            key = (os.path.normpath(parts[0]), parts[1])
            if key in entries:
                problems.append("%s:%d: %s %s is accepted twice" % (ACCEPTED, n, *key))
            entries[key] = parts[2]
    return entries, problems


def stream(text):
    """govulncheck's JSON is concatenated objects, not an array."""
    decoder, i, out = json.JSONDecoder(), 0, []
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return out
        obj, i = decoder.raw_decode(text, i)
        out.append(obj)


def scan(module, command):
    """{ID: the dependency module it was found in}, for one tool module."""
    try:
        run = subprocess.run(command, cwd=module, capture_output=True, text=True)
    except OSError as e:
        raise CannotCheck("%s: could not run %s: %s" % (module, command[0], e))
    if run.returncode != 0:
        # 3 is the TEXT format's "found something" exit, which -format json never
        # uses; it means the flag went missing, not that the scan ran and found.
        hint = " (the text format's findings exit: is -format json still in the recipe?)" \
            if run.returncode == 3 else ""
        raise CannotCheck("%s: govulncheck exited %d%s\n%s"
                          % (module, run.returncode, hint, run.stderr.strip()))
    try:
        objects = stream(run.stdout)
    except ValueError as e:
        raise CannotCheck("%s: output is not govulncheck's JSON (is -format json "
                          "still in the recipe?): %s" % (module, e))
    # The run has to prove it was the scan this verdict is about: a symbol scan
    # given a pattern also exits 0 and would be read as this one, and an empty
    # stdout parses as no findings at all.
    levels = [o["config"].get("scan_level") for o in objects if "config" in o]
    if levels != ["module"]:
        raise CannotCheck("%s: expected one module-level scan, got scan_level %s"
                          % (module, levels or "none"))
    found = {}
    for o in objects:
        if "finding" in o:
            trace = o["finding"].get("trace") or [{}]
            found[o["finding"]["osv"]] = trace[0].get("module", "?")
    return found


def check(command):
    modules = sorted(os.path.dirname(p) for p in glob.glob(MODULES))
    if not modules:
        raise CannotCheck("no %s found; run from the repository root" % MODULES)
    entries, problems = accepted()

    lines, seen = [], set()
    for module in modules:
        found = scan(module, command)
        seen.update((module, osv) for osv in found)
        for osv, dep in sorted(found.items()):
            if (module, osv) in entries:
                lines.append("%s: %s in %s accepted — %s" % (module, osv, dep, entries[(module, osv)]))
            else:
                problems.append("%s: %s in %s is NEW; fix it (bump %s), or accept it in %s "
                                "with its reason" % (module, osv, dep, dep, ACCEPTED))
        if not found:
            lines.append("%s: no advisories" % module)
    for m, osv in sorted(entries.keys() - seen):
        where = "the scan no longer finds it" if m in modules else "there is no such module"
        problems.append("%s: %s is accepted in %s but %s; delete the line"
                        % (m, osv, ACCEPTED, where))
    return lines, problems


def main():
    if len(sys.argv) < 2:
        print("usage: vuln_tools.py <govulncheck> -scan module -format json", file=sys.stderr)
        return 2
    try:
        lines, problems = check(sys.argv[1:])
    except CannotCheck as e:
        print("vuln-tools: COULD NOT CHECK — %s" % e, file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 — deliberate, as in toolchain_floor.py
        # Load-bearing, not habit: an uncaught exception exits 1, the code a real
        # finding uses. The likeliest one is a govulncheck upgrade reshaping its
        # JSON (a KeyError on "osv"), which is could-not-check, not a finding.
        print("vuln-tools: COULD NOT CHECK — %s: %s" % (type(e).__name__, e), file=sys.stderr)
        return 2
    for line in lines:
        print("vuln-tools: " + line)
    for problem in problems:
        print("vuln-tools: FAIL " + problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
