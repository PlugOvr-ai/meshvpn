#!/usr/bin/env python3
"""Plays the browser for `meshvpn desktop <node>`: connects to the viewer's WebSocket and
runs a scripted session. Prints a JSON summary for the test to check.

    desktop_client.py PORT TOKEN
"""
import base64, json, os, select, socket, struct, sys, time

S_INIT, S_TILE, S_FRAME_END, S_WINDOWS, S_CLIPBOARD, S_CURSOR, S_APPS, S_NOTICE = range(1, 9)
C_POINTER, C_WHEEL, C_KEY, C_CLIPBOARD, C_ACTIVATE, C_CLOSE, C_LAUNCH, C_ACK, C_REFRESH, C_RESIZE = range(101, 111)


class Viewer:
    def __init__(self, port, token):
        self.s = socket.create_connection(("127.0.0.1", port), 10)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET /ws?token={token} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
                        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += self.s.recv(1)
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise SystemExit(f"no websocket: {head[:80]!r}")
        self.buf = b""
        self.size = None; self.windows = []; self.apps = None; self.clip = None; self.notices = []
        self.tiles = {1: 0, 2: 0}; self.frames = 0; self.cursor = False

    def send(self, kind, payload=b""):
        data = bytes([kind]) + struct.pack("<I", len(payload)) + payload
        mask = os.urandom(4)
        n = len(data)
        hdr = bytes([0x82]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n))
        self.s.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def pump(self, timeout=0.3):
        r, _, _ = select.select([self.s], [], [], timeout)
        if r:
            d = self.s.recv(1 << 20)
            if not d:
                raise SystemExit(json.dumps({"error": "connection closed", "notices": self.notices}))
            self.buf += d
        while len(self.buf) >= 2:
            ln, off = self.buf[1] & 0x7F, 2
            if ln == 126:
                ln, off = struct.unpack(">H", self.buf[2:4])[0], 4
            elif ln == 127:
                ln, off = struct.unpack(">Q", self.buf[2:10])[0], 10
            if len(self.buf) < off + ln:
                break
            m, self.buf = self.buf[off:off + ln], self.buf[off + ln:]
            self.handle(m[0], m[5:])

    def handle(self, kind, p):
        if kind == S_INIT: self.size = list(struct.unpack("<HH", p[:4]))
        elif kind == S_TILE: self.tiles[p[8]] = self.tiles.get(p[8], 0) + 1
        elif kind == S_FRAME_END: self.frames += 1; self.send(C_ACK)
        elif kind == S_WINDOWS: self.windows = json.loads(p)
        elif kind == S_CLIPBOARD: self.clip = p.decode()
        elif kind == S_CURSOR: self.cursor = True
        elif kind == S_APPS: self.apps = json.loads(p)
        elif kind == S_NOTICE: self.notices.append(p.decode())

    def until(self, cond, what, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return
            self.pump()
        raise SystemExit(json.dumps({"error": f"timeout: {what}", "notices": self.notices, "windows": self.windows}))

    def settle(self, secs):
        end = time.time() + secs
        while time.time() < end:
            self.pump(0.1)

    def key(self, keysym, char):
        for down in (1, 0):
            self.send(C_KEY, bytes([down, char]) + struct.pack("<I", keysym))


def xfce(port, token):
    """Xfce session: its windows as tabs, typing into its terminal, survives the browser closing."""
    v = Viewer(port, token)
    v.send(C_RESIZE, struct.pack("<HH", 1280, 800))
    v.until(lambda: v.size == [1280, 800] and v.frames >= 1, "first frame", 90)
    v.settle(8)  # Xfce starting
    panels_hidden = v.windows == []
    v.send(C_LAUNCH, b"xfce4-terminal")
    v.until(lambda: any("Terminal" in w["title"] for w in v.windows), "the Xfce terminal as a tab", 60)
    v.settle(2)
    for ch in "echo typed-in-xfce > /tmp/xfce_typed":
        v.key(ord(ch), 1)
    v.key(0xFF0D, 0)
    v.settle(1)
    v.send(C_LAUNCH, b"thunar")
    v.until(lambda: any("Thunar" in w["title"] for w in v.windows), "Thunar", 60)
    first = [w["title"] for w in v.windows]
    v.s.close()
    # The browser went away; a new one sees the same windows.
    v2 = Viewer(port, token)
    v2.send(C_RESIZE, struct.pack("<HH", 1280, 800))
    v2.until(lambda: v2.frames >= 1 and len(v2.windows) >= 2, "the same windows after reconnecting", 30)
    print(json.dumps({"panels_hidden": panels_hidden, "first": first, "again": [w["title"] for w in v2.windows],
                      "notices": v.notices + v2.notices}))


def main():
    port, token = int(sys.argv[1]), sys.argv[2]
    if len(sys.argv) > 3 and sys.argv[3] == "xfce":
        return xfce(port, token)
    v = Viewer(port, token)
    v.send(C_RESIZE, struct.pack("<HH", 1000, 640))
    v.until(lambda: v.size == [1000, 640] and v.frames >= 1, "first frame at the requested size", 90)
    first = dict(v.tiles)
    v.send(C_LAUNCH, b"xterm -e sh -c 'cat > /tmp/typed'")
    v.until(lambda: len(v.windows) == 1, "the xterm window")
    v.settle(1.5)
    for ch in "Hello Wörld €!":
        v.key(ord(ch) if ord(ch) < 256 else 0x1000000 + ord(ch), 1)
    v.key(0xFF0D, 0)  # Enter
    v.send(C_CLIPBOARD, "from the browser ✓".encode())
    v.settle(0.5)
    v.send(C_LAUNCH, b"xclip -o -selection clipboard > /tmp/clip_in")
    v.settle(1.5)
    v.send(C_LAUNCH, b"printf 'from an X app' | xclip -i -selection clipboard")
    v.until(lambda: v.clip == "from an X app", "clipboard from the desktop")
    v.send(C_LAUNCH, b"xlogo")
    v.until(lambda: len(v.windows) == 2 and v.windows[-1]["title"] == "xlogo" and v.windows[-1]["active"], "xlogo on top")
    v.send(C_CLOSE, struct.pack("<I", v.windows[-1]["id"]))
    v.until(lambda: len(v.windows) == 1 and v.windows[0]["active"], "xlogo closed, xterm active again")
    v.send(C_RESIZE, struct.pack("<HH", 800, 500))
    v.until(lambda: v.size == [800, 500], "resized")
    v.settle(1)
    print(json.dumps({"size": v.size, "first_frame_tiles": first, "tiles": v.tiles, "frames": v.frames,
                      "cursor": v.cursor, "apps": [a["name"] for a in v.apps or []], "notices": v.notices}))


if __name__ == "__main__":
    main()
