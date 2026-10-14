#!/usr/bin/env python3
"""Structure-aware Atheris fuzz harness for rarfile (RAR 1.5-3.x era parser).

rarfile parses a header-CRC16-checked binary container, so random bytes never form a valid archive.
This harness SYNTHESIZES a RAR3 archive (marker, main header, 1-3 file headers, end-of-archive) whose
file header fields (method, unpack size, name, CRC, packed data) are all driven by the fuzzed bytes,
writes it to a temp file and then lists and READS every entry with RarFile.read().

Reading goes through rarfile's two extraction paths: stored entries (method 0x30) are read directly in
Python (DirectReader); every other method is decompressed by the `unrar` tool and streamed through a
pipe (PipeReader).  RarExtFile documents "no short reads - .read() reads as much as requested", so the
oracle asserts that a read() which does not raise returns exactly the entry's declared size.
"""
import os
import struct
import sys
import tempfile
import zlib

import atheris

import fuzz_helpers  # noqa: F401  (Atheris utilities shipped with the original fuzz-rar target)

with atheris.instrument_imports(include=["rarfile"]):
    import rarfile

_SIG = b"Rar!\x1a\x07\x00"
_LONG_BLOCK = 0x8000


def _block(btype: int, flags: int, body: bytes) -> bytes:
    size = 7 + len(body)
    tail = struct.pack("<BHH", btype, flags, size) + body
    return struct.pack("<H", zlib.crc32(tail) & 0xFFFF) + tail


def _file_block(fdp) -> bytes:
    data = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 600))
    method = fdp.PickValueInList([0x30, 0x31, 0x32, 0x33, 0x33, 0x34, 0x35])
    unp_ver = fdp.PickValueInList([15, 20, 26, 29])
    file_size = fdp.ConsumeIntInRange(0, 0x4000)
    if method == 0x30:
        file_size = len(data)
    crc = fdp.ConsumeIntInRange(0, 0xFFFFFFFF)
    if method == 0x30 and fdp.ConsumeBool():
        crc = zlib.crc32(data) & 0xFFFFFFFF
    name = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 24)).replace(b"\0", b"_").replace(b"/", b"_")
    name = name.replace(b"\\", b"_").replace(b"-", b"_") or b"f"
    host_os = fdp.ConsumeIntInRange(0, 3)
    dostime = fdp.ConsumeIntInRange(0, 0xFFFFFFFF)
    attr = fdp.ConsumeIntInRange(0, 0xFFFF)
    flags = _LONG_BLOCK
    body = struct.pack("<LLBLLBBHL", len(data), file_size, host_os, crc, dostime,
                       unp_ver, method, len(name), attr) + name
    # LONG_BLOCK: the packed size (first body field) doubles as the block's add_size
    tail = struct.pack("<BHH", 0x74, flags, 7 + len(body)) + body
    return struct.pack("<H", zlib.crc32(tail) & 0xFFFF) + tail + data


def _build_rar3(fdp) -> bytes:
    out = [_SIG, _block(0x73, 0, b"\0" * 6)]
    for _ in range(fdp.ConsumeIntInRange(1, 3)):
        out.append(_file_block(fdp))
    out.append(_block(0x7B, 0, b""))
    return b"".join(out)


def TestOneInput(data: bytes) -> None:
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        archive = _build_rar3(fdp)
    except Exception:
        return

    fd, path = tempfile.mkstemp(suffix=".rar")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(archive)
        try:
            rf = rarfile.RarFile(path)
            infos = rf.infolist()
            rf.namelist()
            rf.needs_password()
            _ = rf.comment
            for info in infos:
                if info.isdir():
                    continue
                try:
                    got = rf.read(info)
                except rarfile.Error:
                    continue
                assert len(got) == info.file_size, (
                    "short read: got %d of %d bytes" % (len(got), info.file_size))
        except rarfile.Error:
            pass
        except (ValueError, EOFError, OSError):
            pass
    finally:
        os.unlink(path)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
