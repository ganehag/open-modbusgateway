# Open MQTT to Modbus Gateway

`openmmg` accepts Modbus requests on MQTT and forwards them to Modbus TCP or
RTU devices. It is a small C daemon built on [libmosquitto](https://mosquitto.org/)
and [libmodbus](https://libmodbus.org/).

It started as a replacement for Teltonika's `modbusgateway`, but it is now its
own project and is not protocol-compatible with that program.

The gateway is deliberately conservative: a request must match an explicit
rule before it reaches a device. MQTT authentication is useful, but it is not a
substitute for limiting what may be read or written.

## Build and run

Install the usual build tools plus development packages for CUnit, libmodbus,
libmosquitto, and Lua 5.1–5.4. Then:

```sh
autoreconf -fi
./configure --prefix=/usr
make
make check
```

Run the daemon with an explicit configuration file while setting it up:

```sh
src/openmmg -c /etc/openmmg/openmmg.conf
```

`src/openmmg.conf.example` is a starting point. Without `-c`, the daemon also
looks for `/etc/openmmg/openmmg.conf`, `/etc/openmmg/settings.conf`, and
`./openmmg.conf`.

Useful development checks:

```sh
make check
make integration-check
make coverage       # requires gcovr
```

The integration test creates virtual serial ports, starts a local Mosquitto
broker, and exercises RTU filtering, concurrent requests, and Lua automation.

## MQTT request format

Publish requests to the configured request topic. Replies are published on the
configured response topic. Fields are whitespace-separated; register values for
functions 15 and 16 are comma-separated and contain no spaces.

### Modbus TCP

```text
0 COOKIE IP_TYPE IP PORT TIMEOUT SLAVE_ID FUNCTION ADDRESS COUNT_OR_VALUE [VALUES]
```

`IP_TYPE` is `0` for IPv4, `1` for IPv6, and `2` for a hostname. `ADDRESS` is
one-based, as it is in most Modbus documentation; the gateway converts it for
libmodbus.

Example: read two holding registers from unit 1 at 192.0.2.10:502:

```text
0 1001 0 192.0.2.10 502 5 1 3 1 2
```

### Modbus RTU

```text
1 COOKIE SERIAL_ID TIMEOUT SLAVE_ID FUNCTION ADDRESS COUNT_OR_VALUE [VALUES]
```

`SERIAL_ID` names a `config serial_gateway` entry. Its device and line settings
come from the configuration, never from the MQTT message. A fixed `slave_id`
in that entry replaces the one in the message.

```text
1 1002 boiler 5 1 3 1 2
```

Supported functions are 1, 2, 3, 4, 5, 6, 15, and 16. Read requests allow up
to 125 values; functions 15 and 16 allow up to 123. The parser rejects extra
fields, malformed numbers, and out-of-range values.

### Replies

```text
COOKIE OK
COOKIE OK VALUE [VALUE ...]
COOKIE ERROR: MESSAGE
```

Write requests return `OK`. Read requests return one value per requested coil
or register. Rejected requests get an error reply using the same cookie whenever
the cookie could be parsed.

## Access rules and security

No rule means no access. TCP and serial rules are separate: a serial rule does
not permit TCP traffic, and vice versa.

A rule covers a target, slave ID, function, and register range. For reads and
multi-value writes, the whole requested span must fit inside the range. A rule
for registers `1-10` does not permit a ten-register request starting at 10.

Use TLS for the MQTT connection in production. The gateway accepts `tlsv1.2`
when TLS is configured and verifies the broker certificate by default. Keep
broker ACLs tight too: clients that do not need to issue Modbus requests should
not be allowed to publish to the request topic.

RTU traffic to the same serial device is serialized. Different devices may run
in parallel. `max_inflight_requests` limits all active Modbus transactions; a
new request receives a capacity error when the limit is reached.

Treat the configuration file as sensitive when it contains MQTT passwords or
client keys. Do not put live credentials in the example configuration.

## Configuration

The format is intentionally small:

```text
config section_name
    option name 'value'
```

Section and option names are exact. Unknown options, bad booleans, and malformed
numeric values make configuration loading fail rather than being ignored.

Here is a minimal RTU configuration:

```text
config mqtt
    option host '127.0.0.1'
    option port '1883'
    option request_topic 'request'
    option response_topic 'response'
    option max_inflight_requests '20'

config serial_gateway
    option id 'boiler'
    option device '/dev/ttyUSB0'
    option baudrate '9600'
    option parity 'even'
    option data_bits '8'
    option stop_bits '1'
    option slave_id '1'

config rule
    option serial_id 'boiler'
    option slave_id '1'
    option function '3'
    option register_address '1-100'
```

`config mqtt` supports `host`, `port`, `keepalive`, `max_inflight_requests`,
`username`, `password`, `client_id`, `qos`, `retain`, `mqtt_protocol`,
`tls_version`, `clean_session`, certificate paths, `verify_ca_cert`,
`request_topic`, and `response_topic`.

`config serial_gateway` requires `id` and `device`; it also accepts `baudrate`,
`parity` (`none`, `even`, or `odd`), `data_bits`, `stop_bits`, and an optional
fixed `slave_id`.

Each `config rule` has `slave_id`, `function`, and `register_address`, plus
either TCP target fields (`ip` and optional `port`) or a `serial_id`. Register
and port options accept a number, a range such as `10-20`, or a comma-separated
list of ranges.

## Lua automation

An optional Lua script can observe the gateway and adjust requests. Lua 5.1
through 5.4 are supported.

```text
config automation
    option script '/etc/openmmg/automation.lua'
```

Lifecycle callbacks include `on_gateway_started`, `on_gateway_stopping`,
`on_mqtt_connected`, `on_mqtt_disconnected`, `on_request_accepted`,
`on_request_rejected`, `on_modbus_succeeded`, `on_modbus_failed`, and
`on_timer`.

Request callbacks run in this order:

```text
on_before_request
on_before_read | on_before_write
on_before_<function>
Modbus operation
on_after_request
on_after_read | on_after_write
on_after_<function>
```

Before callbacks may change the address, count, or values in the request table,
or return `false, "reason"` to reject it. The gateway validates and filters the
changed request again. Endpoint, unit ID, function, and cookie remain under
gateway control.

Scripts may use `gateway.read_registers(address, count)`,
`gateway.write_registers(address, values)`, and
`gateway.write_registers_to(target, address, values)` for permitted auxiliary
work. See `examples/automation.lua.example` for an inactivity-reset example.

Lua automation is a build-time option: pass `--enable-lua` to `configure`.
Without it, the gateway has no Lua runtime dependency and refuses a configured
automation script at startup. The Lua environment does not expose `io`, `os`,
`package`, or `debug`; dynamic script loading is disabled. Callbacks have an
instruction budget and the Lua state has a 1 MiB memory limit.

## OpenWrt

The `openwrt/` directory contains the package recipe. It uses OpenWrt's
Autotools support, builds the daemon without its host-only CUnit suite, and
installs the binary, UCI configuration, and procd service. Its **Lua automation
support** package option adds the Lua dependency and passes `--enable-lua`.
Copy the *contents* of `openwrt/` into an OpenWrt source tree under
`package/utils/open-modbusgateway`, select the package in `make menuconfig`,
and build it with:

```sh
mkdir -p package/utils/open-modbusgateway
cp -a /path/to/open-modbusgateway/openwrt/. package/utils/open-modbusgateway/
make package/open-modbusgateway/compile V=s
```
