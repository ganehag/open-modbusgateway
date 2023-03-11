<p align="center">
    <img src="https://raw.githubusercontent.com/ganehag/open-modbusgateway/master/docs/images/timmy.svg" alt="Open Modbus Gateway" width="300" />
    <br>
    <br>
    <quote>&ldquo;Open Modbus Gateway, a bridge between two worlds, connecting the security efficiency of MQTT with the simplicity of Modbus, the gateway/bridge allows for seamless communication and data flow between devices, opening up new possibilities for automation and optimization.&rdquo;</quote>
</p>

---


# Open MQTT to Modbus Gateway

This software is an Open Source alternative to Teltonikas' Modbus Gateway (`modbusgateway`).

It is written in C and uses the [libmodbus](https://libmodbus.org/) library. It also depends on the [libmosquitto](https://mosquitto.org/) library for MQTT communication.

This software used to be a drop-in replacement for the Teltonika Modbus Gateway software, but it has since been rewritten and is no longer compatible.

> **NOTE:** This software is not affiliated with Teltonika, and I've not seen a single line of Teltonika code.


## Background

The Teltonika RUT's `modbusgateway` software is a crucial component of the product offering at my company.

I don't know why Teltonika developed it in the first place, the requirements, or the design decisions behind it. All I know is that it doesn't (at the time of writing) support all typical Modbus functions. I raised this problem with them in February 2021, but it is still unresolved.

Instead of waiting for a fix, I created my own software to fill the gap.


## Benefits over the original software

At first, it was nothing more than a drop-in replacement for the original software, with support for the missing Modbus functions. However, with time I realised that some security layer was required to prevent unwanted commands to Modbus slaves. Along with that came the need for a rules engine to filter out unwanted requests. While I was at it, I also added support for TLS so that the software no longer needs to rely on a separate MQTT broker.

* Supports all Modbus functions
* Is open source
* Supports TLS without the need for a separate MQTT broker
* Rules engine for advanced filtering of requests


## Protocol

A `controller` publishes a message in the format below on a `request` topic. The software interprets the message and performs a Modbus request based on instructions from the message. The software then replies on the `response` topic.

### Request message

`0 <COOKIE> <IP_TYPE> <IP> <PORT> <TIMEOUT> <SLAVE_ID> <MODBUS_FUNCTION> <REGISTER_NUMBER> <REGISTER_COUNT/VALUE> <DATA>`

| Field                | Value                                      | Explanation                                                                                                                                                                                                                                                                                                                                                           |
|----------------------|--------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0                    | 0                                          | Must be 0, which signifies a textual format (currently the only one implemented).                                                                                                                                                                                                                                                                                     |
| COOKIE               | 64-bit unsigned integer in range [0..2^64] | A cookie is used to distinguish which response belongs to which request. Each request and the corresponding response contain a matching cookie: a 64-bit unsigned integer.                                                                                                                                                                                            |
| IP_TYPE              | 0, 1, 2                                    | Host IP address type. Possible values: 0 (IPv4 address), 1 (IPv6 address), 2 (hostname pointing to an IP address).                                                                                                                                                                                                                                                    |
| IP                   | IP address                                 | IP address of a Modbus TCP slave. IPv6 must be presented in full form (e.g., 2001:0db8:0000:0000:0000:8a2e:0370:7334).                                                                                                                                                                                                                                                |
| PORT                 | port number                                | Port number of the Modbus TCP slave.                                                                                                                                                                                                                                                                                                                                  |
| TIMEOUT              | timeout in seconds                         | Timeout for Modbus TCP connection, in seconds. Range [1..999].                                                                                                                                                                                                                                                                                                        |
| SLAVE_ID             | Modbus TCP slave ID                        | Modbus TCP slave ID. Range [1..255].                                                                                                                                                                                                                                                                                                                                  |
| MODBUS_FUNCTION      | 1, 2, 3, 4, 5, 6, 15, 16                   | Modbus function. Possible values: 1 (read coils), 2 (read discret inputs), 3 (read holding registers), 4 (read input registers), 5 (force/write single coil), 6 (preset/write a single holding register), 15 (force/write multiple coils), 16 (preset/write to multiple holding registers)                                                                            |
| REGISTER_NUMBER      | register number                            | Number of the first register (in the range [1..65536]) from which the registers will be read/written.                                                                                                                                                                                                                                                                 |
| REGISTER_COUNT/VALUE | coil/register count or value               | This value depends on the Modbus function: 1, 2, 3, 4 (coil/register count in range [1..125]), 5 (coil value in range [0..1]), 6 (register value in range [0..65535]), 15 (register count in range [1..123]), 16 (register count in range [1..123]). Must not exceed the boundary (first register number + register count <= 65537)                                   |
| DATA                 | series of coil/register values             | This field only exists for Modbus functions 15 (coil) and 16 (register). A series of coil/register values separated with commas, without spaces (e.g., 0,1,1,0,0,1 or 1,2,3,654,21,789). There must be exactly as many values as specified in register count. Each coil value must be in the range of [0..1]. Each register value must be in the range of [0..65535]. |


### Response message

`<COOKIE> OK`

`<COOKIE> OK <VALUE> <VALUE> <VALUE>`

`<COOKIE> ERROR <ERROR_CODE>`

| Field    | Value                   | Explanation                                                                                                                                                                |
|----------|-------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| COOKIE   | 64-bit unsigned integer | A cookie is used to distinguish which response belongs to which request. Each request and the corresponding response contain a matching cookie: a 64-bit unsigned integer. |
| Function | 5, 6, 15, 16            | For functions 5, 6, 15 and 16, the response will be "&lt;COOKIE&gt; OK"                                                                                                    |
| Function | 1, 2, 3, 4              | For functions 1, 2, 3, 4, the response will be "&lt;COOKIE&gt; OK &lt;VALUE&gt; &lt;VALUE&gt; &lt;VALUE&gt; ..." where &lt;VALUE&gt; are the values                        |
| Error    |                         | For failures, the response will be "&lt;COOKIE&gt; ERROR: &lt;message&gt;" where &lt;message&gt; is the error description.                                                 |


## Examples


| Action                                  | Request                                               | Response                            |
|-----------------------------------------|-------------------------------------------------------|-------------------------------------|
| Reading five coils                      | 0 16468394968118163995 0 10.0.0.126 5020 5 1 1 1 5    | 16468394968118163995 OK 1 1 1 1 1   |
| Reading three input registers           | 0 9958479625634 0 10.0.0.126 5020 5 1 4 1 3           | 9958479625634 OK 1234 5678 9101     |
| Sending too few holding register values | 0 565842596387 0 10.0.0.126 5020 5 1 16 1 3 1234,5678 | 565842596387 ERROR: INVALID REQUEST |


## Security

Modbus is a protocol that is not secure by default. There is no authentication or encryption in the Modbus protocol.

This software uses MQTT to relay messages to a Modbus TCP slave from the internet. MQTT is capable of being a secure protocol, but only if the MQTT broker and client both support TLS encryption.

TLS encryption is supported and tested against the [test.mosquitto.org](https://test.mosquitto.org/) broker on port 8884.

Still, even with encryption, one shouldn't just trust any message sent to the gateway. Otherwise, the gateway would blindly relay the message to the Modbus TCP slave. Even a simple misspelling of a register number could cause damage to the Modbus TCP slave.

To get around this, the gateway has built-in checks to filter out messages. A message must pass the following checks to be relayed to the Modbus TCP slave:

- CIDR check: the IP address of the request target must be within the specified CIDR range.
- Port check: the port number of the request target must be within the specified range.
- Slave ID check: the slave ID of the request must match the specified slave ID.
- Function check: the Modbus function of the request must match and be only one of the following: 1, 2, 3, 4, 5, 6, 15 or 16.
- Register number check: the register number must be within the specified range.

The checks are configurable via the configuration file. The configuration file is described in the next section.


## Configuration

The config file is used to specify the settings for the application. The file must be in plain text format.

### Format

The file is divided into sections, each section starts with a `config` keyword followed by the name of the section.
Each section contains multiple options, each option is specified on a new line and starts with the `option` keyword followed by the name of the option and its value.

```text
config <section_name>
	option <option_name> '<option_value>'
	option <option_name> '<option_value>'
	...
```

Example config file:

```text
config mqtt
	option host '127.0.0.1'
	option port '1883'
	option keepalive '60'
	option username 'user'
	option password 'pass'
	option qos '0'
	option retain 'false'
	option clean_session 'true'
	option request_topic 'request'
	option response_topic 'response'
	option ca_cert_path 'cert/ca.crt'
	option cert_path 'cert/client.crt'
	option key_path 'cert/client.key'

config rule
	option ip '::ffff:127.0.0.1/128'
	option port '1502'
	option slave_id '1'
	option function '3'
	option register_address '0-65535'
```

### Sections

- `mqtt`: This section contains the settings for the MQTT connection. It has the following options:
  - `host`: The hostname or IP address of the MQTT broker.
  - `port`: The port number of the MQTT broker.
  - `keepalive`: The keepalive interval in seconds.
  - `username`: The username for the MQTT broker.
  - `password`: The password for the MQTT broker.
  - `client_id`: The client ID for the MQTT connection.
  - `qos`: The quality of service for the MQTT connection. Must be either 0, 1 or 2.
  - `retain`: Whether to retain the MQTT messages. Must be either true or false.
  - `mqtt_protocol`: The MQTT protocol version to use. Must be either 3.1, 3.1.1, or 5.
  - `tls_version`: The TLS version to use. For OpenSSL >= 1.0.1, the available options are tlsv1.2, tlsv1.1, and tlsv1, with tlsv1.2 being the default. For OpenSSL < 1.0.1, the available options are tlsv1 and sslv3, with tlsv1 being the default.
  - `clean_session`: Whether to use a clean session for the MQTT connection. Must be either true or false.
  - `ca_cert_path`: The path to the CA certificate file. If this option is not specified, the CA certificate will not be used.
  - `cert_path`: The path to the certificate file. If this option is not specified, the certificate will not be used.
  - `key_path`: The path to the key file. If this option is not specified, the key will not be used.
  - `verify`: Whether to verify the server certificate. Should not be used in production.
  - `request_topic`: The topic used for receiving requests.
  - `response_topic`: The topic used to send responses.

- `mqtt`: This section contains the settings for the MQTT connection. It has the following options:
  - `host`: The hostname or IP address of the MQTT broker.
  - `port`: The port number of the MQTT broker.
  - `keepalive`: The keepalive interval in seconds.
  - `username`: The username for the MQTT broker.
  - `password`: The password for the MQTT broker.
  - `qos`: The quality of service for the MQTT connection. Must be either 0, 1 or 2.
  - `retain`: Whether to retain the MQTT messages. Must be either `true` or `false`.
  - `clean_session`: Whether to use a clean session for the MQTT connection. Must be either `true` or `false`.
  - `request_topic`: The topic used for receiving requests.
  - `response_topic`: The topic used to send responses.
  - `ca_cert_path`: The path to the CA certificate file. If this option is not specified, the CA certificate will not be used.
  - `cert_path`: The path to the certificate file. If this option is not specified, the certificate will not be used.
  - `key_path`: The path to the key file. If this option is not specified, the key will not be used.

- `rule`: This section contains the settings for the Modbus communication filtering. It can appear multiple times in the config file. Each section has the following options:
  - `ip`: The IP address of the Modbus device, it must be an IPv6 address or an IPv4 address encoded in IPv6 format, and it must also include a subnet mask.
  - `port`: The port number of the Modbus device. It can be a single number or a range of numbers separated by a '-'.
  - `slave_id`: The slave ID of the Modbus device.
  - `function`: The function code used for the Modbus communication.
  - `register_address`: The range of register addresses used for the Modbus communication, it should be in the form of 'start-end'.
