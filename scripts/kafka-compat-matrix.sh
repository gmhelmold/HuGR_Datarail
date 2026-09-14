#!/usr/bin/env bash
# Run or validate real-client compatibility matrix entries.
# Adapters must accept --broker, --topic, --data-dir and print exactly one version marker plus one result marker:
# DATARAIL_COMPAT_VERSION=<exact client version> and DATARAIL_COMPAT_RESULT=PASS or DATARAIL_COMPAT_RESULT=FAIL.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MATRIX="$SCRIPT_DIR/kafka-compat-matrix.tsv"
BROKER_BIN="${DATARAIL_BIN:-$REPO_ROOT/target/release/datarail}"
PORT="${DATARAIL_PORT:-19092}"
TOPIC="${DATARAIL_TOPIC:-compat-matrix}"

usage() {
    printf '%s\n' \
        "Usage:" \
        "  $0 --check [--matrix FILE]" \
        "  $0 --run ID [--matrix FILE] [--broker-bin FILE] [--tool NAME] [--adapter FILE]" \
        "  $0 --classify-result FILE"
}

die() {
    printf 'ERROR: %s\n' "$1" >&2
    exit 1
}

classify_result() {
    local result_file="$1"
    local adapter_rc="$2"
    local expected_version="$3"
    local version_markers
    local actual_version
    local pass_markers
    local fail_markers
    version_markers="$(grep -Ec '^DATARAIL_COMPAT_VERSION=.+$' "$result_file" || true)"
    actual_version="$(grep -E '^DATARAIL_COMPAT_VERSION=.+$' "$result_file" || true)"
    pass_markers="$(grep -Fxc 'DATARAIL_COMPAT_RESULT=PASS' "$result_file" || true)"
    fail_markers="$(grep -Fxc 'DATARAIL_COMPAT_RESULT=FAIL' "$result_file" || true)"

    if [ "$version_markers" -ne 1 ]; then
        printf 'UNKNOWN\n'
        return 3
    fi
    if [ "$expected_version" != "-" ] && [[ "$actual_version" != *"$expected_version"* ]]; then
        printf 'UNKNOWN\n'
        return 3
    fi
    if [ "$adapter_rc" -eq 0 ] && [ "$pass_markers" -eq 1 ] && [ "$fail_markers" -eq 0 ]; then
        printf 'PASS\n'
        return 0
    fi
    if [ "$pass_markers" -eq 0 ] && [ "$fail_markers" -eq 1 ]; then
        printf 'FAIL\n'
        return 1
    fi
    printf 'UNKNOWN\n'
    return 3
}

check_matrix() {
    local expected_header header rows seen_ids line id client status expected_version version_command tool adapter scope evidence extra required
    [ -f "$MATRIX" ] || die "matrix missing: $MATRIX"
    expected_header=$'# id\tclient\tstatus\texpected_version\tversion_command\ttool\tadapter\tscope\tevidence'
    header=""
    rows=0
    seen_ids="|"
    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        if [ -z "$header" ]; then
            header="$line"
            [ "$header" = "$expected_header" ] || die "matrix header mismatch"
            continue
        fi
        case "$line" in
            \#*) continue ;;
        esac

        IFS=$'\t' read -r id client status expected_version version_command tool adapter scope evidence extra <<< "$line"
        [ -n "${id:-}" ] || die "empty id in matrix"
        [ -z "${extra:-}" ] || die "too many columns for $id"
        [ -n "${client:-}" ] || die "$id has empty client"
        [ -n "${status:-}" ] || die "$id has empty status"
        [ -n "${version_command:-}" ] || die "$id has empty version_command"
        [ -n "${tool:-}" ] || die "$id has empty tool"
        [ -n "${adapter:-}" ] || die "$id has empty adapter"
        [ -n "${scope:-}" ] || die "$id has empty scope"
        [ -n "${evidence:-}" ] || die "$id has empty evidence"
        case "$status" in
            PASS|FAIL|UNAVAILABLE|UNTESTED|UNKNOWN) ;;
            *) die "$id has unknown status: $status" ;;
        esac
        case "$seen_ids" in
            *"|$id|"*) die "duplicate id: $id" ;;
        esac
        seen_ids="$seen_ids$id|"
        case "$status" in
            PASS)
                [ "$expected_version" != "-" ] || die "$id PASS lacks expected version"
                [ "$version_command" != "-" ] || die "$id PASS lacks version capture"
                case "$evidence" in
                    No\ *) die "$id PASS has untested evidence" ;;
                esac
                ;;
        esac
        rows=$((rows + 1))
    done < "$MATRIX"

    [ "$rows" -gt 0 ] || die "matrix has zero data rows"
    for required in kcat-librdkafka-1.7.1 librdkafka-1.8.0-independent apache-kafka-java franz-go kafka-python sarama librdkafka-2.x transactional-eos; do
        case "$seen_ids" in
            *"|$required|"*) ;;
            *) die "required matrix row missing: $required" ;;
        esac
    done
    printf 'MATRIX OK: %s rows\n' "$rows"
}

read_row() {
    local wanted_id="$1"
    local found=1
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|'#'*) continue ;;
        esac
        [ "$line" = '# id	client	status	expected_version	version_command	tool	adapter	scope	evidence' ] && continue
        IFS=$'\t' read -r row_id row_client _row_status row_expected_version _row_version_command row_tool row_adapter _row_scope _row_evidence extra <<< "$line"
        if [ "$row_id" = "$wanted_id" ]; then
            found=0
            break
        fi
    done < "$MATRIX"
    [ "$found" -eq 0 ] || die "matrix row missing: $wanted_id"
}

run_one() {
    local id="$1"
    local override_tool="$2"
    local override_adapter="$3"
    local row_client row_expected_version row_tool row_adapter
    local tool adapter data_dir broker_pid result_file ready adapter_rc
    read_row "$id"
    tool="${override_tool:-$row_tool}"
    adapter="${override_adapter:-$row_adapter}"

    if [ "$tool" = "-" ] || ! command -v "$tool" >/dev/null 2>&1; then
        printf '%s\t%s\tUNAVAILABLE\tclient tool missing: %s\n' "$id" "$row_client" "${tool:--}"
        return 2
    fi
    if [ "$adapter" = "-" ] || [ ! -x "$adapter" ]; then
        printf '%s\t%s\tUNAVAILABLE\tadapter missing: %s\n' "$id" "$row_client" "${adapter:--}"
        return 2
    fi
    [ -x "$BROKER_BIN" ] || die "broker binary missing or not executable: $BROKER_BIN"

    data_dir="$(mktemp -d)"
    broker_pid=""
    result_file="$data_dir/adapter.result"
    cleanup() {
        if [ -n "$broker_pid" ] && kill -0 "$broker_pid" 2>/dev/null; then
            kill "$broker_pid" 2>/dev/null || true
            wait "$broker_pid" 2>/dev/null || true
        fi
        rm -rf "$data_dir"
    }
    trap cleanup RETURN

    "$BROKER_BIN" kafka-broker "$REPO_ROOT/examples/rail.toml" \
        --listen "127.0.0.1:$PORT" --advertised 127.0.0.1 \
        --data-dir "$data_dir" --partitions 1 >"$data_dir/broker.log" 2>&1 &
    broker_pid=$!
    ready=0
    for _ in $(seq 1 50); do
        if bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
            ready=1
            break
        fi
        sleep 0.2
    done
    [ "$ready" -eq 1 ] || die "broker did not listen on 127.0.0.1:$PORT"

    set +e
    "$adapter" --broker "127.0.0.1:$PORT" --topic "$TOPIC" --data-dir "$data_dir" >"$result_file" 2>&1
    adapter_rc=$?
    set -e
    printf '%s\n' "--- adapter output ($id) ---"
    cat "$result_file"
    printf '%s\t%s\t' "$id" "$row_client"
    classify_result "$result_file" "$adapter_rc" "$row_expected_version"
}

mode=""
id=""
override_tool=""
override_adapter=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --check) mode=check; shift ;;
        --run) mode=run; [ "$#" -ge 2 ] || die "--run needs ID"; id="$2"; shift 2 ;;
        --classify-result) mode=classify; [ "$#" -ge 2 ] || die "--classify-result needs FILE"; result_file="$2"; shift 2 ;;
        --matrix) [ "$#" -ge 2 ] || die "--matrix needs FILE"; MATRIX="$2"; shift 2 ;;
        --broker-bin) [ "$#" -ge 2 ] || die "--broker-bin needs FILE"; BROKER_BIN="$2"; shift 2 ;;
        --tool) [ "$#" -ge 2 ] || die "--tool needs NAME"; override_tool="$2"; shift 2 ;;
        --adapter) [ "$#" -ge 2 ] || die "--adapter needs FILE"; override_adapter="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$mode" in
    check) check_matrix ;;
    run)
        [ -n "$id" ] || die "--run needs ID"
        check_matrix >/dev/null
        run_one "$id" "$override_tool" "$override_adapter"
        ;;
    classify)
        [ -f "$result_file" ] || die "result file missing: $result_file"
        classify_result "$result_file" 0 "-"
        ;;
    *) usage >&2; exit 1 ;;
esac
