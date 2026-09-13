#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE=${DATARAIL_DURABILITY_IMAGE:-rust:1.90-bookworm}

command -v docker >/dev/null 2>&1 || {
    printf '%s\n' 'DUR-01: docker is required' >&2
    exit 2
}
docker info >/dev/null 2>&1 || {
    printf '%s\n' 'DUR-01: docker daemon unavailable' >&2
    exit 2
}

docker run --rm --privileged \
    -v "$ROOT:/src" \
    -w /src \
    "$IMAGE" \
    bash -ceu '
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dmsetup e2fsprogs util-linux
        cargo build --release -p datarail-substrate-wal --example durability_probe

        image=/tmp/datarail-device-mapper.img
        dm_name=datarail-fault-$RANDOM-$RANDOM
        loop=
        mounted=0
        cleanup() {
            set +e
            if [ "$mounted" -eq 1 ]; then
                umount -l /mnt/datarail-fault
            fi
            dmsetup remove --deferred "$dm_name"
            if [ -n "$loop" ]; then
                losetup -d "$loop"
            fi
            rm -f "$image"
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
        dmsetup reload "$dm_name" --table "0 $sectors error"
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
        printf "DUR-01 device-mapper cut: PASS (%s acknowledged records)\n" "$acked"
    '
