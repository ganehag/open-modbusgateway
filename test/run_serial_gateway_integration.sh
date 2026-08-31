#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d -t openmmg-integration-XXXXXX)"

CLEANUP_PIDS=()

if [[ ! -x "$ROOT_DIR/src/openmmg" ]]; then
    echo "[INFO] Building openmmg binary"
    if ! make -C "$ROOT_DIR/src" >/dev/null; then
        echo "[ERROR] Failed to build src/openmmg" >&2
        exit 1
    fi
fi

cleanup() {
    for pid in "${CLEANUP_PIDS[@]}"; do
        kill "$pid" >/dev/null 2>&1 || true
    done
    rm -rf -- "$TMPDIR"
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
CLEANUP_PIDS+=("$SOCAT_PID")
sleep 1

echo "[INFO] Building RTU slave simulator"
gcc -o "$TMPDIR/rtu_slave_sim" "$ROOT_DIR/test/rtu_slave_sim.c" -lmodbus

echo "[INFO] Starting RTU slave simulator on $SLAVE_DEV"
"$TMPDIR/rtu_slave_sim" "$SLAVE_DEV" 115200 E 8 1 3 100 \
    &> "$TMPDIR/rtu_slave.log" &
SLAVE_PID=$!
CLEANUP_PIDS+=("$SLAVE_PID")
sleep 1

CONF_FILE="$TMPDIR/openmmg.conf"
AUTOMATION_SCRIPT="$TMPDIR/automation.lua"
cat > "$AUTOMATION_SCRIPT" <<'EOF'
local watched_register = 1
local last_write_ms
local reset_target

function on_modbus_succeeded(event)
    if event.function_code == 16 and event.register_address == watched_register then
        last_write_ms = event.timestamp_ms
        reset_target = event.target
    end
end

function on_timer(event)
    if not reset_target or not last_write_ms
       or event.timestamp_ms - last_write_ms < 1000 then
        return
    end
    last_write_ms = nil
    assert(gateway.write_registers_to(reset_target, watched_register, { 0 }))
end
EOF
cat > "$CONF_FILE" <<EOF
config mqtt
    option host '127.0.0.1'
    option port '$PORT'
    option reconnect_delay '1'
    option request_topic 'request'
    option response_topic 'response'

config automation
    option script '$AUTOMATION_SCRIPT'

config serial_gateway
    option id '$SERIAL_ID'
    option device '$MASTER_DEV'
    option baudrate '115200'
    option parity 'even'
    option data_bits '8'
    option stop_bits '1'
    option slave_id '3'

config rule
    option serial_id '$SERIAL_ID'
    option slave_id '3'
    option function '3'
    option register_address '1-10'

config rule
    option serial_id '$SERIAL_ID'
    option slave_id '3'
    option function '16'
    option register_address '1-10'
EOF

echo "[INFO] Starting openmmg with config $CONF_FILE"
"$ROOT_DIR/src/openmmg" -c "$CONF_FILE" -d \
    &> "$TMPDIR/openmmg.log" &
OPENMMG_PID=$!
CLEANUP_PIDS+=("$OPENMMG_PID")
sleep 1

if ! kill -0 "$OPENMMG_PID" 2>/dev/null; then
    echo "[ERROR] openmmg exited while the broker was unavailable."
    cat "$TMPDIR/openmmg.log"
    exit 1
fi

echo "[INFO] Launching mosquitto broker on port $PORT"
/usr/sbin/mosquitto -p "$PORT" -v \
    &> "$TMPDIR/mosquitto.log" &
MOSQUITTO_PID=$!
CLEANUP_PIDS+=("$MOSQUITTO_PID")
sleep 2

RESPONSE_FILE="$TMPDIR/response.txt"
echo "[INFO] Subscribing to MQTT response topic"
timeout 20 mosquitto_sub -h 127.0.0.1 -p "$PORT" -t response -C 1 \
    > "$RESPONSE_FILE" &
SUB_PID=$!
CLEANUP_PIDS+=("$SUB_PID")
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

CONCURRENT_RESPONSE_FILE="$TMPDIR/concurrent_responses.txt"
echo "[INFO] Verifying concurrent RTU requests are serialized"
timeout 20 mosquitto_sub -h 127.0.0.1 -p "$PORT" -t response -C 4 \
    > "$CONCURRENT_RESPONSE_FILE" &
CONCURRENT_SUB_PID=$!
CLEANUP_PIDS+=("$CONCURRENT_SUB_PID")
sleep 1
CONCURRENT_PUBLISH_PIDS=()
for CONCURRENT_COOKIE in 123456793 123456794 123456795 123456796; do
    mosquitto_pub -h 127.0.0.1 -p "$PORT" -t request \
        -m "1 $CONCURRENT_COOKIE $SERIAL_ID 5 3 3 1 2" &
    CONCURRENT_PUBLISH_PIDS+=("$!")
done
for CONCURRENT_PUBLISH_PID in "${CONCURRENT_PUBLISH_PIDS[@]}"; do
    wait "$CONCURRENT_PUBLISH_PID"
done
if ! wait "$CONCURRENT_SUB_PID"; then
    echo "[ERROR] Timed out waiting for concurrent RTU responses."
    exit 1
fi
for CONCURRENT_COOKIE in 123456793 123456794 123456795 123456796; do
    if ! grep -qx "$CONCURRENT_COOKIE OK 100 200" "$CONCURRENT_RESPONSE_FILE"; then
        echo "[ERROR] Missing successful response for concurrent request $CONCURRENT_COOKIE"
        cat "$CONCURRENT_RESPONSE_FILE"
        exit 1
    fi
done
echo "[INFO] Concurrent RTU serialization test passed"

RESET_WRITE_COOKIE=123456791
RESET_WRITE_FILE="$TMPDIR/reset_write.txt"
timeout 20 mosquitto_sub -h 127.0.0.1 -p "$PORT" -t response -C 1 \
    > "$RESET_WRITE_FILE" &
RESET_WRITE_SUB_PID=$!
CLEANUP_PIDS+=("$RESET_WRITE_SUB_PID")
sleep 1
echo "[INFO] Verifying automation resets an inactive register"
mosquitto_pub -h 127.0.0.1 -p "$PORT" -t request \
    -m "1 $RESET_WRITE_COOKIE $SERIAL_ID 5 3 16 1 1 55"
wait "$RESET_WRITE_SUB_PID"

sleep 3
RESET_READ_COOKIE=123456792
RESET_READ_FILE="$TMPDIR/reset_read.txt"
timeout 20 mosquitto_sub -h 127.0.0.1 -p "$PORT" -t response -C 1 \
    > "$RESET_READ_FILE" &
RESET_READ_SUB_PID=$!
CLEANUP_PIDS+=("$RESET_READ_SUB_PID")
sleep 1
mosquitto_pub -h 127.0.0.1 -p "$PORT" -t request \
    -m "1 $RESET_READ_COOKIE $SERIAL_ID 5 3 3 1 1"
wait "$RESET_READ_SUB_PID"
RESET_RESPONSE="$(cat "$RESET_READ_FILE")"
if [[ "$RESET_RESPONSE" != "$RESET_READ_COOKIE OK 0" ]]; then
    echo "[ERROR] Inactivity reset failed: '$RESET_RESPONSE'"
    exit 1
fi
echo "[INFO] Automation reset integration test passed: $RESET_RESPONSE"

BLOCKED_COOKIE=123456790
BLOCKED_RESPONSE_FILE="$TMPDIR/blocked_response.txt"
echo "[INFO] Verifying serial filter blocks an out-of-range request"
timeout 20 mosquitto_sub -h 127.0.0.1 -p "$PORT" -t response -C 1 \
    > "$BLOCKED_RESPONSE_FILE" &
BLOCKED_SUB_PID=$!
CLEANUP_PIDS+=("$BLOCKED_SUB_PID")
sleep 1

BLOCKED_REQUEST="1 $BLOCKED_COOKIE $SERIAL_ID 5 3 3 11 1"
mosquitto_pub -h 127.0.0.1 -p "$PORT" -t request -m "$BLOCKED_REQUEST"

if ! wait "$BLOCKED_SUB_PID"; then
    echo "[ERROR] Timed out waiting for blocked-request response."
    exit 1
fi

BLOCKED_RESPONSE="$(cat "$BLOCKED_RESPONSE_FILE")"
EXPECTED_BLOCKED_RESPONSE="$BLOCKED_COOKIE ERROR: MESSAGE BLOCKED"

if [[ "$BLOCKED_RESPONSE" != "$EXPECTED_BLOCKED_RESPONSE" ]]; then
    echo "[ERROR] Unexpected blocked response: '$BLOCKED_RESPONSE' (expected '$EXPECTED_BLOCKED_RESPONSE')"
    exit 1
fi

echo "[INFO] Serial filter integration test passed: $BLOCKED_RESPONSE"

echo "[INFO] Verifying graceful shutdown while the broker is unavailable"
kill "$MOSQUITTO_PID"
wait "$MOSQUITTO_PID" || true
sleep 2
kill -TERM "$OPENMMG_PID"
if ! wait "$OPENMMG_PID"; then
    echo "[ERROR] openmmg reported failure during graceful shutdown."
    cat "$TMPDIR/openmmg.log"
    exit 1
fi
echo "[INFO] Graceful disconnected shutdown test passed"
