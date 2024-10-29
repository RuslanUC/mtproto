# pyMTProto

This is a Telegram MTProto protocol library inspired by [h11](https://github.com/python-hyper/h11).

This library implements the following MTProto transports:
- Abridged
- Intermediate
- Padded Intermediate
- Full
- Obfuscated versions of all above (except Full)

## Installation
```shell
pip install mtproto
```
Note that in order to use obfuscated transports or encrypt/decrypt mtproto messages,
you MUST specify at least one (if you install both, only tgcrypto will be used) 
a crypto library in square brackets (currently tgcrypto and pyaes are supported):
```shell
pip install mtproto[tgcrypto]
```
or 
```shell
pip install mtproto[pyaes]
```

## Usage
```python
from os import urandom

from mtproto import Connection, ConnectionRole
from mtproto.transports import IntermediateTransport
from mtproto.packets import UnencryptedMessagePacket

conn = Connection(
    ConnectionRole.CLIENT,
    # Transport class to use, supported: AbridgedTransport, IntermediateTransport, PaddedIntermediateTransport, FullTransport
    # Default is AbridgedTransport. You need to specify transport class only if you are using ConnectionRole.CLIENT role.
    transport_cls=IntermediateTransport,
    # Whether to use transport obfuscation or not. Default is False. Obfuscation for FullTransport is not supported now. 
    transport_obf=False,
)

to_send = conn.send(UnencryptedMessagePacket(
    message_id=123456789,
    message_data=b"\xbe\x7e\x8e\xf1"[::-1] + urandom(16)  # req_pq_multi#be7e8ef1 nonce:int128
))

# Send data to telegram server
...
# Receive data from telegram server
received = ...
packet = conn.receive(received)

print(packet)
# UnencryptedMessagePacket(message_id=..., message_data=b"...")
```