"""A minimal Nostr relay for the e2e tests (Python standard library only, plain ws://).

Keeps the newest event per (pubkey, kind, d tag), drops expired ones (NIP-40), answers REQ
with kinds/authors/#d/limit filters. With --auth it asks for a NIP-42 login first and serves
an author's events only to a connection logged in with that key (as NIP-78 suggests). It
doesn't check signatures: meshvpn checks them itself. Every event received is logged (one JSON
line) to stdout.

    python3 nostr_relay.py [--port 7777] [--auth]
    python3 nostr_relay.py --connect-proxy 3128     # an HTTP proxy (CONNECT only), logs each one
"""
import base64, hashlib, json, os, socketserver, struct, sys, threading, time

PORT = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 7777
AUTH = "--auth" in sys.argv
store, lock = {}, threading.Lock()


def tag(ev, name):
    for t in ev.get("tags", []):
        if len(t) >= 2 and t[0] == name:
            return t[1]
    return None


def expired(ev):
    exp = tag(ev, "expiration")
    return exp is not None and int(exp) < time.time()


def matches(ev, f):
    if "kinds" in f and ev["kind"] not in f["kinds"]:
        return False
    if "authors" in f and ev["pubkey"] not in f["authors"]:
        return False
    for k, vals in f.items():
        if k.startswith("#") and tag(ev, k[1:]) not in vals:
            return False
    return True


class Conn(socketserver.StreamRequestHandler):
    def send(self, obj):
        data = json.dumps(obj).encode()
        head = bytes([0x81])
        n = len(data)
        head += bytes([n]) if n < 126 else (bytes([126]) + struct.pack(">H", n) if n < 65536 else bytes([127]) + struct.pack(">Q", n))
        self.wfile.write(head + data)
        self.wfile.flush()

    def frame(self):
        b = self.rfile.read(2)
        if len(b) < 2:
            return None, None
        op, n = b[0] & 0x0F, b[1] & 0x7F
        if n == 126:
            n = struct.unpack(">H", self.rfile.read(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", self.rfile.read(8))[0]
        mask = self.rfile.read(4) if b[1] & 0x80 else b"\0\0\0\0"
        data = bytes(c ^ mask[i % 4] for i, c in enumerate(self.rfile.read(n)))
        return op, data

    def handle(self):
        headers = {}
        line = self.rfile.readline()
        while True:
            h = self.rfile.readline().decode().strip()
            if not h:
                break
            k, _, v = h.partition(":")
            headers[k.strip().lower()] = v.strip()
        key = headers.get("sec-websocket-key", "")
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.wfile.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                          f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
        self.wfile.flush()
        challenge, authed = os.urandom(8).hex(), set()
        if AUTH:
            self.send(["AUTH", challenge])
        while True:
            op, data = self.frame()
            if op is None or op == 8:
                return
            if op == 9:
                self.wfile.write(bytes([0x8A, len(data)]) + data)
                continue
            if op != 1:
                continue
            try:
                msg = json.loads(data)
            except ValueError:
                continue
            if msg[0] == "AUTH":
                ev = msg[1]
                ok = ev.get("kind") == 22242 and tag(ev, "challenge") == challenge
                if ok:
                    authed.add(ev["pubkey"])
                self.send(["OK", ev.get("id", ""), ok, "" if ok else "invalid: bad login"])
            elif msg[0] == "EVENT":
                ev = msg[1]
                if AUTH and ev["pubkey"] not in authed:
                    self.send(["OK", ev["id"], False, "auth-required: log in first"])
                    continue
                if expired(ev):
                    self.send(["OK", ev["id"], False, "invalid: expired"])
                    continue
                print(json.dumps({"event": ev}), flush=True)
                k = (ev["pubkey"], ev["kind"], tag(ev, "d"))
                with lock:
                    old = store.get(k)
                    if old is None or ev["created_at"] >= old["created_at"]:
                        store[k] = ev
                self.send(["OK", ev["id"], True, ""])
            elif msg[0] == "REQ":
                sub, filters = msg[1], msg[2:]
                if AUTH and any(a not in authed for f in filters for a in f.get("authors", [None])):
                    self.send(["CLOSED", sub, "auth-required: log in first"])
                    continue
                with lock:
                    evs = [e for e in store.values() if not expired(e) and any(matches(e, f) for f in filters)]
                for e in sorted(evs, key=lambda e: -e["created_at"]):
                    self.send(["EVENT", sub, e])
                self.send(["EOSE", sub])


class Proxy(socketserver.StreamRequestHandler):
    def handle(self):
        import socket
        line = self.rfile.readline().decode().strip()
        while self.rfile.readline().strip():
            pass
        method, target = (line.split() + ["", ""])[:2]
        if method != "CONNECT":
            self.wfile.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        host, _, port = target.rpartition(":")
        try:
            up = socket.create_connection((host.strip("[]"), int(port)), timeout=10)
        except OSError:
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        print(json.dumps({"connect": target}), flush=True)
        self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        self.wfile.flush()
        up.settimeout(None)

        def pump(src, dst):
            try:
                while (b := src.recv(65536)):
                    dst.sendall(b)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        t = threading.Thread(target=pump, args=(up, self.connection), daemon=True)
        t.start()
        pump(self.connection, up)
        t.join()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    if "--connect-proxy" in sys.argv:
        port = int(sys.argv[sys.argv.index("--connect-proxy") + 1])
        print(f"proxy on {port}", flush=True)
        Server(("0.0.0.0", port), Proxy).serve_forever()
    print(f"relay on {PORT}{' (auth)' if AUTH else ''}", flush=True)
    Server(("0.0.0.0", PORT), Conn).serve_forever()
