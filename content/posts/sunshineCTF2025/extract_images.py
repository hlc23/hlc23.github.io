#!/usr/bin/env python3
"""
Extract images from a pcapng capture.

Features:
- Uses scapy's PcapNgReader to stream-parse packets with low memory.
- Reassembles TCP by sequence numbers per-direction.
- Parses HTTP responses: Content-Length and chunked transfer-encoding.
- Extracts image bodies by Content-Type and also via magic-signature scanning.
- Deduplicates outputs by SHA1.

Output: ./extracted_images/image_<n>.<ext>

Limitations:
- Encrypted traffic (HTTPS/TLS) is not supported.
- Some edge HTTP cases (e.g., multipart) are not fully handled.
"""
from __future__ import annotations

import os
import re
import sys
import io
import hashlib
from typing import Dict, List, Tuple, Iterable, Optional

try:
    from scapy.all import TCP, Raw  # type: ignore
    from scapy.utils import PcapNgReader  # type: ignore
except Exception as e:  # pragma: no cover
    print("[ERROR] scapy is required. Install with: pip install scapy", file=sys.stderr)
    raise


def ensure_outdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


class TCPStream:
    """Accumulates TCP payloads for a single direction using sequence ordering."""

    def __init__(self) -> None:
        self.segments: List[Tuple[int, bytes]] = []  # (seq, payload)

    def add(self, seq: int, payload: bytes) -> None:
        if not payload:
            return
        self.segments.append((seq, payload))

    def build(self) -> bytes:
        if not self.segments:
            return b""
        # Sort by seq, then coalesce with simple overlap handling
        self.segments.sort(key=lambda x: x[0])
        buf = io.BytesIO()
        current_end = None  # type: Optional[int]
        for seq, data in self.segments:
            if current_end is None:
                buf.write(data)
                current_end = seq + len(data)
                continue
            if seq >= current_end:
                buf.write(data)
                current_end = seq + len(data)
            else:
                # overlap; write only the new tail beyond current_end
                overlap = current_end - seq
                if overlap < len(data):
                    tail = data[overlap:]
                    buf.write(tail)
                    current_end += len(tail)
                else:
                    # fully duplicate segment; skip
                    pass
        return buf.getvalue()


HTTP_RESP_RE = re.compile(br"HTTP/1\.[01] \d{3} ")


def parse_http_responses(stream: bytes) -> Iterable[Tuple[Dict[str, str], bytes]]:
    """Yield (headers, body) tuples parsed from an HTTP response stream.

    Handles basic Content-Length and Transfer-Encoding: chunked. Tolerates leftover bytes.
    """
    i = 0
    n = len(stream)
    while True:
        m = HTTP_RESP_RE.search(stream, i)
        if not m:
            break
        start = m.start()
        # find headers end
        hdr_end = stream.find(b"\r\n\r\n", start)
        if hdr_end == -1:
            break  # incomplete
        raw_headers = stream[start:hdr_end + 4]
        header_text = raw_headers.split(b"\r\n", 1)[1].decode('iso-8859-1', errors='replace')
        headers: Dict[str, str] = {}
        for line in header_text.split("\r\n"):
            if not line:
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        body_start = hdr_end + 4
        body = b""
        # Determine body by transfer-encoding or content-length
        te = headers.get("transfer-encoding", "").lower()
        if "chunked" in te:
            j = body_start
            chunks = []
            while True:
                crlf = stream.find(b"\r\n", j)
                if crlf == -1:
                    break
                size_line = stream[j:crlf]
                # allow chunk extensions
                semi = size_line.split(b";", 1)[0]
                try:
                    size = int(semi.strip(), 16)
                except ValueError:
                    break
                j = crlf + 2
                if size == 0:
                    # read trailing CRLF after last-chunk
                    # optionally there may be trailer headers; skip until CRLFCRLF or just one CRLF
                    end = stream.find(b"\r\n\r\n", j)
                    if end == -1:
                        # fallback: consume a single CRLF if present
                        if stream[j:j+2] == b"\r\n":
                            j += 2
                    else:
                        j = end + 4
                    body = b"".join(chunks)
                    i = j
                    break
                # ensure enough data
                if j + size > n:
                    # incomplete; stop parsing
                    i = j
                    break
                chunks.append(stream[j:j+size])
                j = j + size
                # chunks are followed by CRLF
                if stream[j:j+2] == b"\r\n":
                    j += 2
                else:
                    # malformed; attempt to continue
                    pass
            else:
                i = j
        elif "content-length" in headers:
            try:
                clen = int(headers["content-length"]) if headers["content-length"].isdigit() else int(headers["content-length"].split(",")[0])
            except Exception:
                clen = 0
            body = stream[body_start: body_start + max(0, clen)]
            i = body_start + max(0, clen)
        else:
            # unknown length; try until next response or end
            next_m = HTTP_RESP_RE.search(stream, body_start)
            end = next_m.start() if next_m else n
            body = stream[body_start:end]
            i = end

        yield headers, body


def guess_ext_from_headers(headers: Dict[str, str]) -> Optional[str]:
    ctype = headers.get("content-type", "").split(";")[0].strip().lower()
    mapping = {
        "image/jpeg": "jpg",
        "image/jpg": "jpg",
        "image/png": "png",
        "image/gif": "gif",
        "image/bmp": "bmp",
        "image/webp": "webp",
        "image/x-icon": "ico",
        "image/vnd.microsoft.icon": "ico",
        "image/tiff": "tiff",
    }
    return mapping.get(ctype)


def find_images_by_magic(data: bytes) -> Iterable[Tuple[str, int, int]]:
    """Find images by signature. Yield (ext, start, end) indices.

    Supported: jpg, png, gif, bmp, webp
    """
    i = 0
    n = len(data)
    # JPEG
    while True:
        start = data.find(b"\xFF\xD8\xFF", i)
        if start == -1:
            break
        end = data.find(b"\xFF\xD9", start + 2)
        if end == -1:
            # no terminator; take a conservative slice up to +4MB
            end = min(n - 1, start + 4 * 1024 * 1024)
        else:
            end += 2
        yield ("jpg", start, end)
        i = end

    # PNG
    i = 0
    png_sig = b"\x89PNG\r\n\x1a\n"
    iend = b"\x00\x00\x00\x00IEND\xAEB`\x82"
    while True:
        start = data.find(png_sig, i)
        if start == -1:
            break
        end = data.find(iend, start)
        if end == -1:
            end = min(n, start + 8 * 1024 * 1024)
        else:
            end += len(iend)
        yield ("png", start, end)
        i = end

    # GIF
    i = 0
    while True:
        start = data.find(b"GIF8", i)
        if start == -1:
            break
        end = data.find(b"\x3B", start)  # GIF trailer
        if end == -1:
            end = min(n, start + 8 * 1024 * 1024)
        else:
            end += 1
        yield ("gif", start, end)
        i = end

    # BMP
    i = 0
    while True:
        start = data.find(b"BM", i)
        if start == -1:
            break
        if start + 6 <= n:
            # size at offset 2 (4 bytes little-endian)
            size = int.from_bytes(data[start+2:start+6], 'little', signed=False)
            end = start + size if 0 < size <= 32 * 1024 * 1024 else min(n, start + 8 * 1024 * 1024)
            yield ("bmp", start, min(n, end))
        i = start + 2

    # WEBP (RIFF container)
    i = 0
    while True:
        start = data.find(b"RIFF", i)
        if start == -1:
            break
        if start + 12 <= n and data[start+8:start+12] == b"WEBP":
            size = int.from_bytes(data[start+4:start+8], 'little', signed=False)
            end = start + 8 + size  # RIFF size excludes 'RIFF' and size field
            end = min(n, end)
            yield ("webp", start, end)
            i = end
        else:
            i = start + 4


def save_blob(outdir: str, idx: int, ext: str, content: bytes, seen: set[str]) -> Optional[str]:
    h = hashlib.sha1(content).hexdigest()
    if h in seen:
        return None
    seen.add(h)
    fname = f"image_{idx:04d}.{ext}"
    path = os.path.join(outdir, fname)
    with open(path, "wb") as f:
        f.write(content)
    return path


def extract_from_pcapng(pcap_path: str, outdir: str) -> List[str]:
    ensure_outdir(outdir)
    flows: Dict[Tuple[str, int, str, int], TCPStream] = {}
    outputs: List[str] = []
    seen_hashes: set[str] = set()

    # 1) Build per-direction TCP byte streams
    with PcapNgReader(pcap_path) as pcap:
        for pkt in pcap:
            try:
                if TCP in pkt and Raw in pkt:
                    ip = pkt.payload  # IP/IPv6
                    if not hasattr(ip, 'src') or not hasattr(ip, 'dst'):
                        continue
                    tcp = pkt[TCP]
                    src = str(ip.src)
                    dst = str(ip.dst)
                    sport = int(tcp.sport)
                    dport = int(tcp.dport)
                    key = (src, sport, dst, dport)
                    stream = flows.get(key)
                    if stream is None:
                        stream = TCPStream()
                        flows[key] = stream
                    payload: bytes = bytes(pkt[Raw].load)
                    seq = int(tcp.seq)
                    stream.add(seq, payload)
            except Exception:
                # Be resilient to malformed packets
                continue

    # 2) For each direction: parse HTTP responses; also signature scan full stream
    idx = 1
    for key, stream in flows.items():
        data = stream.build()
        # 2a) HTTP responses
        for headers, body in parse_http_responses(data):
            ext = guess_ext_from_headers(headers)
            if not ext:
                # try magic
                for ext2, s, e in find_images_by_magic(body):
                    path = save_blob(outdir, idx, ext2, body[s:e], seen_hashes)
                    if path:
                        outputs.append(path)
                        idx += 1
                continue
            # If ext is known, save full body
            if body:
                path = save_blob(outdir, idx, ext, body, seen_hashes)
                if path:
                    outputs.append(path)
                    idx += 1

        # 2b) Global signature scan on the whole stream
        for ext, s, e in find_images_by_magic(data):
            path = save_blob(outdir, idx, ext, data[s:e], seen_hashes)
            if path:
                outputs.append(path)
                idx += 1

    return outputs


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        pcap = os.path.join(os.getcwd(), "evidence.pcapng")
    else:
        pcap = argv[1]
    outdir = os.path.join(os.getcwd(), "extracted_images") if len(argv) < 3 else argv[2]
    if not os.path.exists(pcap):
        print(f"[ERROR] pcapng not found: {pcap}", file=sys.stderr)
        return 2
    print(f"[INFO] Reading: {pcap}")
    print(f"[INFO] Output Dir: {outdir}")
    try:
        outputs = extract_from_pcapng(pcap, outdir)
    except Exception as e:
        print(f"[ERROR] Extraction failed: {e}", file=sys.stderr)
        return 1
    print(f"[DONE] Extracted {len(outputs)} files.")
    if outputs:
        print("First few:")
        for p in outputs[:10]:
            print(" -", os.path.relpath(p))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
