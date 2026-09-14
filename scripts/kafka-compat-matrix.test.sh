#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNNER="$SCRIPT_DIR/kafka-compat-matrix.sh"
MATRIX="$SCRIPT_DIR/kafka-compat-matrix.tsv"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$RUNNER" --check >/dev/null

if output="$($RUNNER --run apache-kafka-java --tool definitely-missing-client --adapter definitely-missing-adapter 2>&1)"; then
    printf 'missing-tool test unexpectedly passed\n' >&2
    exit 1
fi
printf '%s\n' "$output" | grep -Fq $'apache-kafka-java\tApache Kafka Java client\tUNAVAILABLE'

printf 'not a result\n' > "$TMP/unknown.result"
if output="$($RUNNER --classify-result "$TMP/unknown.result" 2>&1)"; then
    printf 'unknown-result test unexpectedly passed\n' >&2
    exit 1
fi
[ "$output" = "UNKNOWN" ]

printf 'DATARAIL_COMPAT_VERSION=client-1.2.3\nDATARAIL_COMPAT_RESULT=PASS\n' > "$TMP/pass.result"
[ "$($RUNNER --classify-result "$TMP/pass.result")" = "PASS" ]

cp "$MATRIX" "$TMP/pass-mutation.tsv"
perl -0pi -e 's/(apache-kafka-java\tApache Kafka Java client\t)UNTESTED/$1PASS/' "$TMP/pass-mutation.tsv"
if "$RUNNER" --check --matrix "$TMP/pass-mutation.tsv" >/dev/null 2>&1; then
    printf 'unavailable-to-pass mutation was not rejected\n' >&2
    exit 1
fi

cp "$MATRIX" "$TMP/version-mutation.tsv"
perl -0pi -e 's/(kcat-librdkafka-1\.7\.1\tkcat \(librdkafka\)\tPASS\t1\.7\.1\t)[^\t]+/$1-/' "$TMP/version-mutation.tsv"
if "$RUNNER" --check --matrix "$TMP/version-mutation.tsv" >/dev/null 2>&1; then
    printf 'version-capture mutation was not rejected\n' >&2
    exit 1
fi

printf 'matrix tests: PASS\n'
