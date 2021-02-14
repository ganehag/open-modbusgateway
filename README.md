# Open Modbus Gateway

This software is an Open Source alternative to Teltonikas' Modbus Gateway (`modbusgateway`).

> **NOTE:** This software is in no way affiliated with Teltonika.


# Background

The `modbusgateway` software of the Teltonika RUT is the critical component of a product package at the company that I work for.

Due to limitations in the original software, it's impossible to `read` or `write` to coils or read from discrete inputs. I wanted to fix this. But due to budget constraints, I could not push through a request to replace the software.

So, I made an Open Source version in my spare time.


# Protocol

A `controller` publishes a message in the format below on a `request` topic. The software interprets the message and performs a Modbus request based on instructions from the message. The software then replies on the `response` topic.

## Request message

`0 <COOKIE> <IP_TYPE> <IP> <PORT> <TIMEOUT> <SLAVE_ID> <MODBUS_FUNCTION> <REGISTER_NUMBER> <REGISTER_COUNT/VALUE> <DATA>`

**Explanation:**  

- **0**: must be 0, which signifies a textual format (currently the only one implemented).
- **Cookie**: a 64-bit unsigned integer in range [0..2^64]). A cookie is used to distinguish which response belongs to which request. Each request and the corresponding response contain a matching cookie: a 64-bit unsigned integer.
- **IP type**: host IP address type. Possible values:
    + *0*: IPv4 address;
    + *1*: IPv6 address;
    + *2*: hostname pointing to an IP address.
- **IP**: IP address of a Modbus TCP slave. IPv6 must be presented in full form (e.g., 2001:0db8:0000:0000:0000:8a2e:0370:7334).
- **Port**: port number of the Modbus TCP slave.
- **Timeout**: timeout for Modbus TCP connection, in seconds. Range [1..999].
- **Slave ID**: Modbus TCP slave ID. Range [1..255].
- **Modbus function**:
    + *1*: read coils
    + *2*: read discret inputs
    + *3*: read holding registers
    + *4*: read input registers
    + *5*: force/write single coil
    + *6*: preset/write a single holding register
    + *15*: force/write multiple coils
    + *16*: preset/write to multiple holding registers
- **Register number**: number of the first register (in the range [1..65536]) from which the registers will be read/written.
- **Register count/value**: this value depends on the Modbus function:
    + *1*, *2*, *3*, *4*: coil/register count (in range [1..125]). Must not exceed the boundary (first register number + register count <= 65537)
    + *5*: coil value (in range [0..1])
    + *6*: register value (in range [0..65535])
    + *15*: register count (in range [1..123])
    + *16*: register count (in range [1..123]). Must not exceed the boundary (first register number + register count <= 65537)
    
- **Data**: this value only exists for Modbus functions *15* (coil) and *16* (register). A series of coil/register values separated with commas, without spaces (e.g., 0,1,1,0,0,1 or 1,2,3,654,21,789). There must be exactly as many values as specified in *register count*. Each coil value must be in the range of [0..1]. Each register value must be in the range of [0..65535].


## Response message

A particular response message can take one of the following forms:

## For functions 5, 6, 15 and 16

    <COOKIE> OK

## For function 1, 2, 3 and 4

    COOKIE> OK <VALUE> <VALUE> <VALUE>

Where <VALUE> <VALUE> <VALUE> are the values read.

## For failures

    COOKIE> ERROR: <message>

Where <message> is the error description.


# Examples

## Reading 5 coils

**Request**  

    0 16468394968118163995 0 10.0.0.126 5020 5 1 1 1 5

**Response**  

    16468394968118163995 OK 1 1 1 1 1

## Reading 3 input registers

**Request**  

    0 9958479625634 0 10.0.0.126 5020 5 1 4 1 3


**Response**  

    9958479625634 OK 1234 5678 9101


## Sending to few holding register values

**Request**  

    0 565842596387 0 10.0.0.126 5020 5 1 16 1 3 1234,5678


**Response**

    565842596387 ERROR: INVALID REQUEST

