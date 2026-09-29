#!/usr/bin/env python3
"""Original mayhemheroes fuzz-rar Atheris harness, ported to v2 (BACKPORT.md, Input-interface
caveat) — the run-4 crashers were produced by THIS harness (raw fuzzed bytes handed straight to
rarfile.RarFile), not the live branch's structure-aware rewrite, so a backport must replay them
against the harness that found them. Verbatim from mayhemheroes/rarfile @ 10c9c88f48e6.
"""
import atheris
import sys
import fuzz_helpers
import random

with atheris.instrument_imports():
    import rarfile


def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        with fdp.ConsumeMemoryFile(all_data=True) as rar:
            rf = rarfile.RarFile(rar)
            for _ in rf.infolist():
                pass
    except ValueError:
        if random.random() > 0.9:
            raise
    except (rarfile.Error):
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
