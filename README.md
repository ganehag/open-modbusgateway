# Open Modbus Gateway

This software is an Open Source alternative to Teltonikas' Modbus Gateway (`modbusgateway`).

It is written in C and uses the [libmodbus](https://libmodbus.org/) library. It also depends on the [libmosquitto](https://mosquitto.org/) library for MQTT communication.

> **NOTE:** This software is in no way affiliated with Teltonika.


# Background

The Teltonika RUT's `modbusgateway` software is a crucial component of the product offering at my company.

Despite the original software having limitations, such as not being able to read from discrete inputs or write or read coils, I was determined to find a solution. However, due to our limited resources and time, replacing the software entirely was not an option.

I took matters into my own hands and, in my spare time, created an open-source version that addresses these limitations and is specifically tailored to our needs.


# Protocol

A `controller` publishes a message in the format below on a `request` topic. The software interprets the message and performs a Modbus request based on instructions from the message. The software then replies on the `response` topic.

## Request message

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


## Response message

`<COOKIE> OK`

`<COOKIE> OK <VALUE> <VALUE> <VALUE>`

`<COOKIE> ERROR <ERROR_CODE>`

| Field    | Value                   | Explanation                                                                                                                                                                |
|----------|-------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| COOKIE   | 64-bit unsigned integer | A cookie is used to distinguish which response belongs to which request. Each request and the corresponding response contain a matching cookie: a 64-bit unsigned integer. |
| Function | 5, 6, 15, 16            | For functions 5, 6, 15 and 16, the response will be "<COOKIE> OK"                                                                                                          |
| Function | 1, 2, 3, 4              | For functions 1, 2, 3, 4, the response will be "<COOKIE> OK <VALUE> <VALUE> <VALUE> ..." where <VALUE> are the values read.                                                |
| Error    |                         | For failures, the response will be "<COOKIE> ERROR: <message>" where <message> is the error description.                                                                   |


# Examples


| Action                                  | Request                                               | Response                            |
|-----------------------------------------|-------------------------------------------------------|-------------------------------------|
| Reading five coils                      | 0 16468394968118163995 0 10.0.0.126 5020 5 1 1 1 5    | 16468394968118163995 OK 1 1 1 1 1   |
| Reading three input registers           | 0 9958479625634 0 10.0.0.126 5020 5 1 4 1 3           | 9958479625634 OK 1234 5678 9101     |
| Sending too few holding register values | 0 565842596387 0 10.0.0.126 5020 5 1 16 1 3 1234,5678 | 565842596387 ERROR: INVALID REQUEST |


# Security

Modbus is a protocol that is not secure by default. There is no authentication or encryption in the Modbus protocol.

This software uses MQTT to relay messages to a Modbus TCP slave from the internet. MQTT is a secure protocol, but it is up to the user to ensure that the MQTT broker is secure. At the moment, this gateway does not support TLS encryption. It only supports plain MQTT with username and password authentication. I will rectify this sometime in the future. In the meantime, using a secure MQTT broker is recommended as a stepping stone to the internet.

Still, one shouldn't just trust any message sent to the gateway. Otherwise, the gateway would blindly relay the message to the Modbus TCP slave. Even a simple misspelling of a register number could cause damage to the Modbus TCP slave.

To get around this, the gateway has built-in checks to filter out messages. A message must pass the following checks to be relayed to the Modbus TCP slave:

- CIDR check: the IP address of the request target must be within the specified CIDR range.
- Port check: the port number of the request target must be within the specified range.
- Slave ID check: the slave ID of the request must match the specified slave ID.
- Function check: the Modbus function of the request must match and be only one of the following: 1, 2, 3, 4, 5, 6, 15 or 16.
- Register number check: the register number must be within the specified range.

The checks are configurable via the configuration file. The configuration file is described in the next section.


# Configuration

FIXME
