from abc import ABC
from os import urandom
from random import randint
from zlib import crc32

from mtproto import ConnectionRole, Connection, transports, Buffer
from mtproto.packets import UnencryptedMessagePacket, QuickAckPacket, ErrorPacket, EncryptedMessagePacket, BasePacket
import pytest as pt

from mtproto.transports.base_transport import BaseTransport


default_parameters_no_full = [
    (transports.AbridgedTransport, False, False,),
    (transports.AbridgedTransport, True, False,),
    (transports.IntermediateTransport, False, False,),
    (transports.IntermediateTransport, True, False,),
    (transports.PaddedIntermediateTransport, False, True,),
    (transports.PaddedIntermediateTransport, True, True,),
]
default_parametrize = pt.mark.parametrize("transport_cls,transport_obf,padded", [
    *default_parameters_no_full,
    (transports.FullTransport, False, False,),
])


def test_no_transport():
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT)

    assert srv.receive(b"") is None
    with pt.raises(ValueError):
        cli.receive(b"")


@default_parametrize
def test_small_unencrypted(transport_cls: type[BaseTransport], transport_obf: bool, padded: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transport_cls, transport_obf=transport_obf)

    message_id = int.from_bytes(urandom(2), "little")
    small_payload = urandom(16)
    to_send = cli.send(UnencryptedMessagePacket(message_id, small_payload))
    received = srv.receive(to_send)
    assert isinstance(received, UnencryptedMessagePacket)
    assert received.message_id == message_id
    if padded:
        assert (received.message_data.startswith(small_payload)
                and (len(received.message_data) - len(small_payload)) < 16)
    else:
        assert received.message_data == small_payload


@pt.mark.parametrize("transport_cls,transport_obf,padded,quick_ack", [
    *[(*params, True) for params in default_parameters_no_full],
    (transports.FullTransport, False, False, False,),
])
def test_quick_ack(
        transport_cls: type[BaseTransport], transport_obf: bool, padded: bool, quick_ack: bool,
):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transport_cls, transport_obf=transport_obf)

    # Client MUST send something first
    assert srv.receive(cli.send(UnencryptedMessagePacket(0, b"1234"))) is not None

    if quick_ack:
        token = b"".join([b"\x80", urandom(2), b"\x80"])
        to_send = srv.send(QuickAckPacket(token))
        received = cli.receive(to_send)
        assert isinstance(received, QuickAckPacket)
        assert received.token == token


@default_parametrize
def test_error(transport_cls: type[BaseTransport], transport_obf: bool, padded: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transport_cls, transport_obf=transport_obf)

    # Client MUST send something first
    assert srv.receive(cli.send(UnencryptedMessagePacket(0, b"1234"))) is not None

    error_code = randint(300, 599)
    to_send = srv.send(ErrorPacket(error_code))
    received = cli.receive(to_send)
    assert isinstance(received, ErrorPacket)
    assert received.error_code == error_code


@default_parametrize
def test_encrypted(transport_cls: type[BaseTransport], transport_obf: bool, padded: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transport_cls, transport_obf=transport_obf)

    key_id = int.from_bytes(urandom(4), "little")
    msg_id = urandom(16)
    data = urandom(32)
    to_send = cli.send(EncryptedMessagePacket(key_id, msg_id, data))
    received = srv.receive(to_send)
    assert isinstance(received, EncryptedMessagePacket)
    assert received.auth_key_id == key_id
    assert received.message_key == msg_id
    if padded:
        assert received.encrypted_data.startswith(data) and (len(received.encrypted_data) - len(data)) < 16
    else:
        assert received.encrypted_data == data


@default_parametrize
def test_receive_empty(transport_cls: type[BaseTransport], transport_obf: bool, padded: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transport_cls, transport_obf=transport_obf)

    # Client MUST send something first
    assert srv.receive(cli.send(UnencryptedMessagePacket(0, b"1234"))) is not None

    assert cli.receive(b"") is None
    assert srv.receive(b"") is None


@default_parametrize
def test_big_unencrypted(transport_cls: type[BaseTransport], transport_obf: bool, padded: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transport_cls, transport_obf=transport_obf)

    message_id = int.from_bytes(urandom(2), "little")
    big_payload = urandom(16 * 1024)
    to_send = cli.send(UnencryptedMessagePacket(message_id, big_payload))
    received = srv.receive(to_send)
    assert isinstance(received, UnencryptedMessagePacket)
    assert received.message_id == message_id
    if padded:
        assert received.message_data.startswith(big_payload) and (len(received.message_data) - len(big_payload)) < 16
    else:
        assert received.message_data == big_payload


@default_parametrize
def test_separate_length(transport_cls: type[BaseTransport], transport_obf: bool, padded: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transport_cls, transport_obf=transport_obf)

    message_id = int.from_bytes(urandom(2), "little")
    small_payload = urandom(16)
    to_send = cli.send(UnencryptedMessagePacket(message_id, small_payload))
    assert srv.receive(to_send[:1]) is None
    assert srv.receive(to_send[1:4]) is None
    received = srv.receive(to_send[4:])
    assert isinstance(received, UnencryptedMessagePacket)
    assert received.message_id == message_id
    if padded:
        assert (received.message_data.startswith(small_payload)
                and (len(received.message_data) - len(small_payload)) < 16)
    else:
        assert received.message_data == small_payload


def test_full_obf_raises() -> None:
    with pt.raises(ValueError):
        cli = Connection(ConnectionRole.CLIENT, transport_cls=transports.FullTransport, transport_obf=True)
        cli.send(ErrorPacket(400))


def test_full_quick_ack_raises() -> None:
    with pt.raises(ValueError):
        cli = Connection(ConnectionRole.CLIENT, transport_cls=transports.FullTransport, transport_obf=False)
        cli.send(QuickAckPacket(b"\x80" * 4))


def test_invalid_transport() -> None:
    class NotSupportedTransport(BaseTransport):
        def read(self, buf: Buffer) -> None:
            return None

        def write(self, packet: BasePacket) -> bytes:
            return b""

    with pt.raises(ValueError):
        cli = Connection(ConnectionRole.CLIENT, transport_cls=NotSupportedTransport, transport_obf=True)
        cli.send(ErrorPacket(400))


def test_full_invalid_seq_no() -> None:
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transports.FullTransport, transport_obf=False)
    to_send = cli.send(ErrorPacket(400))
    to_send = bytearray(to_send)
    to_send[4:8] = (int.from_bytes(to_send[4:8], "little") + 123).to_bytes(4, "little")
    to_send[-4:] = crc32(to_send[:-4]).to_bytes(4, byteorder="little")
    to_send = bytes(to_send)
    assert srv.receive(to_send) is None


def test_full_invalid_crc() -> None:
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transports.FullTransport, transport_obf=False)
    to_send = cli.send(ErrorPacket(400))
    to_send = bytearray(to_send)
    to_send[-4:] = (int.from_bytes(to_send[-4:], "little") + 1).to_bytes(4, "little")
    assert srv.receive(to_send) is None
