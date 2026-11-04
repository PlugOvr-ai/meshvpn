#!/usr/bin/env python3
"""Prints the licences of everything compiled into the meshvpn binary, which most of them ask to come
with it: the licence and notice files of each Rust crate, and of the C library it's statically linked with.
A crate with no licence file of its own gets the standard text of the licence it names, at the end.
Run from the repository (or an extension's, which has this core among its crates)."""
import json
import os
import re
import subprocess
import sys

FILE = re.compile(r"^(licen[cs]e|copying|copyright|notice|unlicense|patents)", re.I)
MUSL = """musl libc (statically linked)
Copyright © 2005-2020 Rich Felker, et al.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""


MIT = """Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
WTFPL = """DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE, Version 2, December 2004
Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>
Everyone is permitted to copy and distribute verbatim or modified copies of this license document, and
changing it is allowed as long as the name is changed.
DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
0. You just DO WHAT THE FUCK YOU WANT TO.
"""


def apache_text(meta):
    """The text of Apache-2.0, as one of the crates ships it."""
    for p in meta["packages"]:
        f = os.path.join(os.path.dirname(p["manifest_path"]), "LICENSE-APACHE")
        if os.path.isfile(f):
            text = open(f, errors="replace").read()
            if "Apache License" in text and "TERMS AND CONDITIONS" in text:
                return text
    sys.exit("no copy of the Apache-2.0 licence found among the crates")


def files(directory):
    found = []
    for base in (directory, os.path.join(directory, "licenses"), os.path.join(directory, "LICENSES")):
        if os.path.isdir(base):
            found += [os.path.join(base, f) for f in sorted(os.listdir(base))
                      if os.path.isfile(os.path.join(base, f)) and (FILE.match(f) or base != directory)]
    return found


def main():
    meta = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1"]))
    resolved = {n["id"] for n in meta["resolve"]["nodes"]}
    ours = set(meta["workspace_members"])
    missing, out = [], []
    for p in sorted(meta["packages"], key=lambda p: (p["name"], p["version"])):
        if p["id"] not in resolved or p["id"] in ours:
            continue
        d = os.path.dirname(p["manifest_path"])
        fs = files(d)
        extra = p.get("license_file")
        if extra and os.path.join(d, extra) not in fs:
            fs.append(os.path.join(d, extra))
        head = f"{'=' * 100}\n{p['name']} {p['version']}: {p.get('license') or 'see below'}\n{p.get('repository') or ''}\n{'=' * 100}\n"
        if not fs:
            # A licence as named by the crate; the texts of these are at the end of this file.
            missing.append(f"{p['name']} {p['version']} ({p.get('license')})")
            out.append(head + "(the crate ships no licence file; its licence is as named above)\n")
            continue
        out.append(head + "\n".join(open(f, errors="replace").read() for f in fs))
    print("Third-party software in meshvpn, and their licences.\n")
    print("=" * 100 + "\n" + MUSL)
    print("\n".join(out))
    if missing:
        print("=" * 100 + "\nCrates with no licence file, under the licence they name:")
        print("\n".join(missing))
        print("\n" + "=" * 100 + "\nThe MIT licence\n\n" + MIT)
        print("=" * 100 + "\nThe WTFPL\n\n" + WTFPL)
        print("=" * 100 + "\nThe Apache License, Version 2.0\n\n" + apache_text(meta))
    print(f"{len(out)} crates, {len(missing)} without a licence file", file=sys.stderr)
    for m in missing:
        print("  " + m, file=sys.stderr)


main()
