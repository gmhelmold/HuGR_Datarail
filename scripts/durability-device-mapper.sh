#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE=${DATARAIL_DURABILITY_IMAGE:-rust:1.90-bookworm}
FAULT_MODE=${DATARAIL_DURABILITY_FAULT_MODE:-cut}

case "$FAULT_MODE" in
    cut|flakey) ;;
    *)
        printf 'DUR-01: unsupported fault mode: %s\n' "$FAULT_MODE" >&2
        exit 2
        ;;
esac

command -v docker >/dev/null 2>&1 || {
    printf '%s\n' 'DUR-01: docker is required' >&2
    exit 2
}
docker info >/dev/null 2>&1 || {
    printf '%s\n' 'DUR-01: docker daemon unavailable' >&2
    exit 2
}

docker run --rm --privileged \
    -e "DATARAIL_DURABILITY_FAULT_MODE=$FAULT_MODE" \
    -v "$ROOT:/src" \
    -w /src \
    "$IMAGE" \
    bash -ceu '
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dmsetup e2fsprogs util-linux
        cargo build --release -p datarail-substrate-wal --example durability_probe

        image=/tmp/datarail-device-mapper.img
        fault_mode=${DATARAIL_DURABILITY_FAULT_MODE:-cut}
        dm_name=datarail-fault-$RANDOM-$RANDOM
        loop=
        mounted=0
        cleanup() {
            cleanup_status=$?
            set +e
            cleanup_failed=0
            if [ "$mounted" -eq 1 ]; then
                umount /mnt/datarail-fault || cleanup_failed=1
            fi
            if dmsetup info "$dm_name" >/dev/null 2>&1; then
                dmsetup remove --deferred "$dm_name" || cleanup_failed=1
                if dmsetup info "$dm_name" >/dev/null 2>&1; then
                    printf "DUR-01: device-mapper mapping remained after cleanup: %s\n" "$dm_name" >&2
                    cleanup_failed=1
                fi
            fi
            if [ -n "$loop" ]; then
                losetup -d "$loop" || cleanup_failed=1
            fi
            rm -f "$image" || cleanup_failed=1
            if [ "$cleanup_failed" -ne 0 ] && [ "$cleanup_status" -eq 0 ]; then
                cleanup_status=1
            fi
            exit "$cleanup_status"
        }
        trap cleanup EXIT

        truncate -s 64M "$image"
        loop=$(losetup --find --show "$image")
        mkfs.ext4 -q "$loop"
        sectors=$(blockdev --getsz "$loop")
        # Docker Desktop kernels may omit dm-flakey. A live linear↔error table switch gives the same cut-I/O
        # boundary without pretending to emulate physical power loss.
        dmsetup create "$dm_name" --table "0 $sectors linear $loop 0"
        dmsetup mknodes "$dm_name"
        mkdir -p /mnt/datarail-fault
        mount "/dev/mapper/$dm_name" /mnt/datarail-fault
        mounted=1
        if [ "$fault_mode" = flakey ]; then
            fstype=$(findmnt -n -o FSTYPE /mnt/datarail-fault)
            case "$fstype" in
                ext4|xfs) ;;
                *)
                    printf "DUR-01: flakey mode requires ext4/xfs, got %s\n" "$fstype" >&2
                    exit 1
                    ;;
            esac
            mount_opts=$(findmnt -n -o OPTIONS /mnt/datarail-fault)
            case ",$mount_opts," in
                *,nobarrier,*|*,barrier=0,*)
                    printf "%s\n" "DUR-01: flakey mode requires filesystem write barriers" >&2
                    exit 1
                    ;;
            esac
            flakey_target=0
            while read -r target _; do
                if [ "$target" = flakey ]; then
                    flakey_target=1
                    break
                fi
            done < <(dmsetup targets)
            if [ "$flakey_target" -ne 1 ]; then
                printf "%s\n" "DUR-01: dm-flakey target unavailable; refusing dm-error fallback" >&2
                exit 1
            fi
        fi

        status=/tmp/datarail-durability-status
        log=/tmp/datarail-durability-writer.log
        rm -f "$status" "$log"
        cargo run --quiet --release -p datarail-substrate-wal --example durability_probe -- \
            write /mnt/datarail-fault/wal "$status" >"$log" 2>&1 &
        writer=$!
        marker=0
        for _ in $(seq 1 60); do
            if [ -s "$status" ]; then
                marker=1
                break
            fi
            if ! kill -0 "$writer" 2>/dev/null; then
                break
            fi
            sleep 1
        done
        if [ "$marker" -eq 0 ]; then
            kill -KILL "$writer" 2>/dev/null || true
            wait "$writer" 2>/dev/null || true
            printf "%s\n" "DUR-01: writer produced no acknowledged marker before cut" >&2
            cat "$log" >&2
            exit 1
        fi
        sleep 1
        dmsetup suspend --nolockfs "$dm_name"
        if [ "$fault_mode" = flakey ]; then
            # One second of healthy I/O, then 300 seconds of dropped I/O. This is a real dm-flakey transition,
            # unlike the portable linear↔error cut used by the macOS Docker fallback.
            dmsetup reload "$dm_name" --table "0 $sectors flakey $loop 0 1 300"
        else
            dmsetup reload "$dm_name" --table "0 $sectors error"
        fi
        dmsetup resume "$dm_name"
        set +e
        writer_status=124
        for _ in $(seq 1 30); do
            if ! kill -0 "$writer" 2>/dev/null; then
                wait "$writer"
                writer_status=$?
                break
            fi
            sleep 1
        done
        if kill -0 "$writer" 2>/dev/null; then
            kill -KILL "$writer"
            wait "$writer"
        fi
        set -e
        dmsetup suspend --nolockfs "$dm_name"
        dmsetup reload "$dm_name" --table "0 $sectors linear $loop 0"
        dmsetup resume "$dm_name"
        umount /mnt/datarail-fault
        mounted=0
        mount "/dev/mapper/$dm_name" /mnt/datarail-fault
        mounted=1
        if [ ! -s "$status" ]; then
            printf "%s\n" "DUR-01: writer produced no acknowledged marker" >&2
            printf "%s\n" "--- writer log ---" >&2
            cat "$log" >&2
            exit 1
        fi
        if [ "$writer_status" -ne 2 ] && [ "$writer_status" -ne 124 ]; then
            printf "DUR-01: writer exit %s, expected controlled I/O fault\n" "$writer_status" >&2
            cat "$log" >&2
            exit 1
        fi
        read -r acked < "$status"
        case "$acked" in
            ""|*[!0-9]*)
                printf "DUR-01: invalid acknowledged-count marker: %s\n" "$acked" >&2
                exit 1
                ;;
        esac
        if [ "$acked" -eq 0 ] || [ "$acked" -ge 256 ]; then
            printf "DUR-01: fault did not cut an active write window: %s\n" "$acked" >&2
            exit 1
        fi

        sleep 6
        cargo run --quiet --release -p datarail-substrate-wal --example durability_probe -- \
            verify /mnt/datarail-fault/wal "$status"
        printf "DUR-01 device-mapper %s: PASS (%s acknowledged records)\n" "$fault_mode" "$acked"
    '
