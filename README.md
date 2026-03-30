# pyMTProto

This is a Telegram MTProto protocol library inspired by [h11](https://github.com/python-hyper/h11).

This library implements the following MTProto transports:
- Abridged
- Intermediate
- Padded Intermediate
- Obfuscated versions of all above
- Full
- HTTP
- Websocket

Also, this library has WIP "bring-your-own-I/O" implementation of the session layer or MTProto protocol.

## Installation

```shell
pip install mtproto
```

Note that in order to use obfuscated transports or encrypt/decrypt mtproto messages,
you MUST specify at least one (if you install both, only tgcrypto will be used) 
crypto library in square brackets (currently `tgcrypto` and `pyaes` are supported):

```shell
pip install mtproto[tgcrypto]
# or
pip install mtproto[pyaes]
```

To use http or websocket transport, you'd need to install `http` or ws `extra`:
```shell
pip install mtproto[http]
# or
pip install mtproto[ws]
```

## Usage
```python
from os import urandom

from mtproto import ConnectionRole
from mtproto.transport import Connection
from mtproto.transport import IntermediateTransport
from mtproto.transport.packets import UnencryptedMessagePacket

conn = Connection(
    ConnectionRole.CLIENT,
    # Transport class to use, supported: 
    #  AbridgedTransport, IntermediateTransport, PaddedIntermediateTransport, FullTransport, HttpTransport, WsTransport
    # Default is AbridgedTransport. You need to specify transport class only if you are using ConnectionRole.CLIENT role.
    #  When role is ConnectionRole.SERVER, transport is ignored
    transport=IntermediateTransport,
    # Whether to use transport obfuscation or not. Default is False. Obfuscation for FullTransport is not supported now. 
    obfuscated=True,
)

to_send = conn.send(UnencryptedMessagePacket(
    message_id=123456789,
    message_data=b"\xbe\x7e\x8e\xf1"[::-1] + urandom(16)  # req_pq_multi#be7e8ef1 nonce:int128
))

# Send data to telegram server
...
# Receive data from telegram server
received = ...
conn.data_received(received)
packet = conn.next_event()

print(packet)
# UnencryptedMessagePacket(message_id=..., message_data=b"...")
```