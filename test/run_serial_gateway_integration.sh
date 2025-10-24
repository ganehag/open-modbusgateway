#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d -t openmmg-integration-XXXXXX)"

CLEANUP_CMDS=()

if [[ ! -x "$ROOT_DIR/src/openmmg" ]]; then
    echo "[INFO] Building openmmg binary"
    if ! make -C "$ROOT_DIR/src" >/dev/null; then
        echo "[ERROR] Failed to build src/openmmg" >&2
        exit 1
    fi
fi

cleanup() {
    for cmd in "${CLEANUP_CMDS[@]}"; do
        eval "$cmd"
    done
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

PORT=18884
COOKIE=123456789
SERIAL_ID="integration"
MASTER_DEV="$TMPDIR/tty_master"
SLAVE_DEV="$TMPDIR/tty_slave"

echo "[INFO] Creating virtual serial link with socat"
socat -d -d PTY,raw,echo=0,link="$MASTER_DEV" PTY,raw,echo=0,link="$SLAVE_DEV" \
    &> "$TMPDIR/socat.log" &
SOCAT_PID=$!
CLEANUP_CMDS+=("kill $SOCAT_PID >/dev/null 2>&1 || true")
sleep 1

echo "[INFO] Building RTU slave simulator"
gcc -o "$TMPDIR/rtu_slave_sim" "$ROOT_DIR/test/rtu_slave_sim.c" -lmodbus

echo "[INFO] Starting RTU slave simulator on $SLAVE_DEV"
"$TMPDIR/rtu_slave_sim" "$SLAVE_DEV" 115200 E 8 1 3 \
    &> "$TMPDIR/rtu_slave.log" &
SLAVE_PID=$!
CLEANUP_CMDS+=("kill $SLAVE_PID >/dev/null 2>&1 || true")
sleep 1

echo "[INFO] Launching mosquitto broker on port $PORT"
/usr/sbin/mosquitto -p "$PORT" -v \
    &> "$TMPDIR/mosquitto.log" &
MOSQUITTO_PID=$!
CLEANUP_CMDS+=("kill $MOSQUITTO_PID >/dev/null 2>&1 || true")
sleep 1

CONF_FILE="$TMPDIR/openmmg.conf"
cat > "$CONF_FILE" <<EOF
config mqtt
    option host '127.0.0.1'
    option port '$PORT'
    option request_topic 'request'
    option response_topic 'response'

config serial_gateway
    option id '$SERIAL_ID'
    option device '$MASTER_DEV'
    option baudrate '115200'
    option parity 'even'
    option data_bits '8'
    option stop_bits '1'
    option slave_id '3'

config rule
    option ip '::ffff:127.0.0.1/128'
    option port '1502'
    option slave_id '1'
    option function '3'
    option register_address '0-10'
EOF

echo "[INFO] Starting openmmg with config $CONF_FILE"
"$ROOT_DIR/src/openmmg" -c "$CONF_FILE" -d \
    &> "$TMPDIR/openmmg.log" &
OPENMMG_PID=$!
CLEANUP_CMDS+=("kill $OPENMMG_PID >/dev/null 2>&1 || true")
sleep 2

RESPONSE_FILE="$TMPDIR/response.txt"
echo "[INFO] Subscribing to MQTT response topic"
timeout 20 mosquitto_sub -h 127.0.0.1 -p "$PORT" -t response -C 1 \
    > "$RESPONSE_FILE" &
SUB_PID=$!
CLEANUP_CMDS+=("kill $SUB_PID >/dev/null 2>&1 || true")
sleep 2

REQUEST="1 $COOKIE $SERIAL_ID 5 3 3 1 2"
echo "[INFO] Publishing request: $REQUEST"
mosquitto_pub -h 127.0.0.1 -p "$PORT" -t request -m "$REQUEST"

if ! wait "$SUB_PID"; then
    echo "[ERROR] Timed out waiting for response."
    echo "----- openmmg log -----"
    cat "$TMPDIR/openmmg.log"
    echo "----- mosquitto log -----"
    cat "$TMPDIR/mosquitto.log"
    echo "----- slave log -----"
    cat "$TMPDIR/rtu_slave.log"
    exit 1
fi

RESPONSE="$(cat "$RESPONSE_FILE")"
EXPECTED="$COOKIE OK 100 200"

if [[ "$RESPONSE" != "$EXPECTED" ]]; then
    echo "[ERROR] Unexpected response: '$RESPONSE' (expected '$EXPECTED')"
    echo "----- openmmg log -----"
    cat "$TMPDIR/openmmg.log"
    echo "----- mosquitto log -----"
    cat "$TMPDIR/mosquitto.log"
    echo "----- slave log -----"
    cat "$TMPDIR/rtu_slave.log"
    exit 1
fi

echo "[INFO] Integration test passed: $RESPONSE"
