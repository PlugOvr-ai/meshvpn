#!/usr/bin/env python3
"""Drives `meshvpn console` in a pseudo-terminal for the tests.

    console_driver.py STEP...   steps: send:<text> (\\r, \\x02 escapes), key:<name>, expect:<text>, wait:<secs>
Exits 1 with the screen text if an expected text doesn't show up.
"""
import os, pty, re, select, struct, sys, time, fcntl, termios

KEYS = {"enter": b"\r", "down": b"\x1b[B", "up": b"\x1b[A", "ctrl-b": b"\x02", "esc": b"\x1b"}
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm-256color"
    os.execvp("meshvpn", ["meshvpn", "console"])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 140, 0, 0))
raw = b""
mark = 0  # expectations look at the output since the last keystroke

def text():
    t = raw[mark:].decode("utf-8", "replace")
    t = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", " ", t)
    return re.sub(r"\x1b[()][A-Z0-9]|\x1b[=>78]", "", t)

def pump(secs):
    global raw
    end = time.time() + secs
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                raw += os.read(fd, 65536)
            except OSError:
                return

pump(2)
for step in sys.argv[1:]:
    kind, _, arg = step.partition(":")
    if kind == "send":
        mark = len(raw)
        os.write(fd, arg.encode().decode("unicode_escape").encode("latin-1"))
        pump(0.3)
    elif kind == "key":
        mark = len(raw)
        os.write(fd, KEYS[arg]); pump(0.3)
    elif kind == "wait":
        pump(float(arg))
    elif kind == "expect":
        end = time.time() + 20
        while arg not in text() and time.time() < end:
            pump(0.3)
        if arg not in text():
            print(f"EXPECTED {arg!r}; screen tail:\n" + text()[-3000:])
            sys.exit(1)
        print(f"ok: {arg}")
os.write(fd, b"\x02" + b"0"); pump(0.3)
os.write(fd, b"q"); pump(0.5); os.write(fd, b"y\r"); pump(1)
