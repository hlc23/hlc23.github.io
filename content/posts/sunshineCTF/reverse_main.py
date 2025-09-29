from __future__ import annotations

import argparse
from pathlib import Path
import os
import sys
import random

# Pipeline in main.c:
#   s = read text of length (filesize + 1) with trailing NUL via fgets
#   flipBits(s, n)
#   s = expand(s, n)  # -> 2n
#   s = expand(s, 2n) # -> 4n
#   s = expand(s, 4n) # -> 8n
#   write 8n bytes to flag.txt
#
# This script inverts the process:
#   data8n --unexpand--> 4n --unexpand--> 2n --unexpand--> n --unflipBits--> original (with trailing NUL)
# N.B. unexpand does NOT need the v3 key; the key nibbles get ORed into the opposite nibble and can be masked out.


def unexpand(buf: bytes) -> bytes:
    """Invert one expand() round.

    Forward (for each input byte x, i from 0..a2-1, v4 toggles starting False):
      if v4 == 0:
        y0 = (v3_low << 4) | (x & 0x0F)
        y1 = (x & 0xF0) | (v3_high)
      else:
        y0 = (x & 0xF0) | (v3_high)
        y1 = (v3_low << 4) | (x & 0x0F)

    Inverse does not need v3, because x's nibbles are preserved:
      if v4 == 0:  x = (y1 & 0xF0) | (y0 & 0x0F)
      else:        x = (y0 & 0xF0) | (y1 & 0x0F)
    """
    if len(buf) % 2 != 0:
        raise ValueError("Buffer length for unexpand must be even")

    out = bytearray(len(buf) // 2)
    v4 = False  # matches C: v4 = 0 initially
    # v3 sequence exists in forward but is irrelevant for inverse

    for i in range(len(out)):
        y0 = buf[2 * i]
        y1 = buf[2 * i + 1]
        if not v4:
            x = (y1 & 0xF0) | (y0 & 0x0F)
        else:
            x = (y0 & 0xF0) | (y1 & 0x0F)
        out[i] = x
        v4 = not v4
    return bytes(out)


def unflip_bits(buf: bytes) -> bytes:
    """Invert flipBits(s, n) from main.c.

    Forward (v4 toggles starting False, v3 starts 105 and increases by 32 on odd steps):
      if not v4: s[i] = ~s[i]
      else:      s[i] ^= v3; v3 += 32

    Inverse mirrors the same toggling and ops.
    """
    out = bytearray(len(buf))
    v4 = False
    v3 = 105  # 0x69
    for i, b in enumerate(buf):
        if not v4:
            out[i] = (~b) & 0xFF
        else:
            out[i] = b ^ (v3 & 0xFF)
            v3 = (v3 + 32) & 0xFF
        v4 = not v4
    return bytes(out)


def reverse_pipeline(data8n: bytes, strip_trailing_nul: bool = True) -> bytes:
    """Reverse three expands and the initial flipBits.

    Returns original data (including the trailing NUL added by fgets). If strip_trailing_nul is True,
    a single trailing NUL byte will be removed when present.
    """
    # 8n -> 4n
    d = unexpand(data8n)
    # 4n -> 2n
    d = unexpand(d)
    # 2n -> n
    d = unexpand(d)
    # undo flipBits
    d = unflip_bits(d)

    if strip_trailing_nul and len(d) > 0 and d[-1] == 0:
        return d[:-1]
    return d


def _expand_forward(buf: bytes) -> bytes:
    """Forward expand from main.c for self-test only."""
    out = bytearray(len(buf) * 2)
    v4 = False
    v3 = 105  # unsigned 8-bit in C; multiplication wraps
    for i, x in enumerate(buf):
        if not v4:
            out[2 * i] = ((v3 & 0x0F) << 4) | (x & 0x0F)
            out[2 * i + 1] = (x & 0xF0) | ((v3 & 0xF0) >> 4)
        else:
            out[2 * i] = (x & 0xF0) | ((v3 & 0xF0) >> 4)
            out[2 * i + 1] = ((v3 & 0x0F) << 4) | (x & 0x0F)
        v3 = (v3 * 11) & 0xFF
        v4 = not v4
    return bytes(out)


def _flip_bits_forward(buf: bytes) -> bytes:
    out = bytearray(len(buf))
    v4 = False
    v3 = 105
    for i, b in enumerate(buf):
        if not v4:
            out[i] = (~b) & 0xFF
        else:
            out[i] = b ^ (v3 & 0xFF)
            v3 = (v3 + 32) & 0xFF
        v4 = not v4
    return bytes(out)


def selftest() -> None:
    rng = random.Random(0xC0FFEE)
    for n in [1, 2, 3, 7, 16, 31, 64, 127, 255]:
        orig = bytes(rng.randrange(0, 256) for _ in range(n))
        # main.c reads with fgets, effectively processing n+1 bytes including NUL
        with_nul = orig + b"\x00"
        f1 = _flip_bits_forward(with_nul)
        e1 = _expand_forward(f1)
        e2 = _expand_forward(e1)
        e3 = _expand_forward(e2)
        rec_keep_nul = reverse_pipeline(e3, strip_trailing_nul=False)
        assert rec_keep_nul == with_nul, f"Roundtrip (keep NUL) failed for n={n}"
        rec = reverse_pipeline(e3, strip_trailing_nul=True)
        assert rec == orig, f"Roundtrip (strip NUL) failed for n={n}"
    print("Self-test passed: roundtrip across various lengths")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Reverse the transformation from main.c (flipBits + expand x3)")
    ap.add_argument("-i", "--input", type=Path, default=Path("flag.txt"), help="Input file (8n bytes), default: flag.txt")
    ap.add_argument("-o", "--output", type=Path, default=Path("recovered_palatinepackflag.txt"), help="Output file for recovered plaintext")
    ap.add_argument("--keep-nul", action="store_true", help="Keep trailing NUL byte instead of stripping it")
    ap.add_argument("--selftest", action="store_true", help="Run internal self-test and exit")
    args = ap.parse_args(argv)

    if args.selftest:
        selftest()
        return 0

    data = args.input.read_bytes()
    if len(data) % 8 != 0:
        print(f"[!] Warning: input length {len(data)} is not a multiple of 8. Proceeding anyway.", file=sys.stderr)

    recovered = reverse_pipeline(data, strip_trailing_nul=not args.keep_nul)
    args.output.write_bytes(recovered)

    # Also print a sanitized preview to stdout
    try:
        preview = recovered.decode("utf-8", errors="replace")
    except Exception:
        preview = recovered.decode("latin-1", errors="replace")

    print(preview)
    print(f"[+] Wrote recovered {len(recovered)} bytes to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
