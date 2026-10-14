#!/usr/bin/env bash
#
# mayhem/test.sh — RUN rarfile's own golden-output test (upstream test/test1.sh: dumprar.py over every
# test/files/*.rar compared with its .exp file; archivers already provisioned by the Dockerfile) and
# emit a CTRF (ctrf.io) summary. exit 0 iff failed==0.
# Behavioral oracle: a no-op patch that neuters rarfile changes the dump, so it FAILS here.
#
# It does NOT compile — build.sh installed atheris into the in-image site dir and
# compiled the rarfile_run_tests ELF wrapper. We only RUN the suite. The suite is routed through that
# compiled NON-system wrapper so the gate's sabotage check (neuter non-system binaries to exit(0))
# actually perturbs the run (the CPython interpreter under /usr/bin would otherwise be spared).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"

SRC="${SRC:-/mayhem}"
cd "$SRC"

# Put the in-image site dir (atheris) and the rarfile source on PYTHONPATH.
PY_PREFIX=/opt/toolchains/python
# shellcheck disable=SC1091
[ -f "$PY_PREFIX/env.sh" ] && source "$PY_PREFIX/env.sh"
export PYTHONPATH="$PY_PREFIX/site:$SRC${PYTHONPATH:+:$PYTHONPATH}"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/rarfile_run_tests"
if [ ! -x "$RUNNER" ]; then
  echo "test.sh: $RUNNER missing/not executable — mayhem/build.sh must build it first" >&2
  emit_ctrf "dumprar-golden" 0 1 0
  exit 1
fi

# rar3-comment-hpsw.rar needs the PyCryptodome `Crypto` module (encrypted headers), which the image
# does not ship: skipped by name; every other archive must match its .exp exactly.
SKIP="rar3-comment-hpsw.rar"

passed=0; failed=0; skipped=0
cd "$SRC/test"
for f in files/*.rar; do
  b="$(basename "$f")"
  if [ "$b" = "$SKIP" ]; then skipped=$((skipped + 1)); continue; fi
  out="$(mktemp)"
  "$RUNNER" ../dumprar.py -t -t -v -ppassword "$f" > "$out" 2>&1
  if [ -s "$out" ] && diff -uw "$f.exp" "$out" > /dev/null; then
    echo "ok   $f"
    passed=$((passed + 1))
  else
    echo "FAIL $f"
    diff -uw "$f.exp" "$out" | head -20
    failed=$((failed + 1))
  fi
  rm -f "$out"
done
cd "$SRC"

emit_ctrf "dumprar-golden" "$passed" "$failed" "$skipped"
