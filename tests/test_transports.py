from os import urandom
from random import randint
from zlib import crc32

from mtproto import ConnectionRole, Connection, transports
from mtproto.packets import UnencryptedMessagePacket, QuickAckPacket, ErrorPacket, EncryptedMessagePacket, BasePacket, \
    DecryptedMessagePacket
import pytest as pt

from mtproto.transports.base_transport import BaseTransport


default_parameters_no_full = [
    (transports.AbridgedTransport, False,),
    (transports.AbridgedTransport, True,),
    (transports.IntermediateTransport, False,),
    (transports.IntermediateTransport, True,),
    (transports.PaddedIntermediateTransport, False,),
    (transports.PaddedIntermediateTransport, True,),
]
default_parametrize = pt.mark.parametrize("transport_cls,transport_obf", [
    *default_parameters_no_full,
    (transports.FullTransport, False,),
])


def test_no_transport():
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT)

    assert srv.receive(b"") is None
    with pt.raises(ValueError):
        cli.receive(b"")


@default_parametrize
def test_small_unencrypted(transport_cls: type[BaseTransport], transport_obf: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transport_cls, transport_obf=transport_obf)

    message_id = int.from_bytes(urandom(2), "little")
    small_payload = urandom(16)
    to_send = cli.send(UnencryptedMessagePacket(message_id, small_payload))
    received = srv.receive(to_send)
    assert isinstance(received, UnencryptedMessagePacket)
    assert received.message_id == message_id
    assert received.message_data == small_payload


@pt.mark.parametrize("transport_cls,transport_obf,quick_ack", [
    *[(*params, True) for params in default_parameters_no_full],
    (transports.FullTransport, False, False,),
])
def test_quick_ack(
        transport_cls: type[BaseTransport], transport_obf: bool, quick_ack: bool,
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
def test_error(transport_cls: type[BaseTransport], transport_obf: bool):
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
def test_encrypted(transport_cls: type[BaseTransport], transport_obf: bool):
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
    assert received.encrypted_data == data


@default_parametrize
def test_receive_empty(transport_cls: type[BaseTransport], transport_obf: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transport_cls, transport_obf=transport_obf)

    # Client MUST send something first
    assert srv.receive(cli.send(UnencryptedMessagePacket(0, b"1234"))) is not None

    assert cli.receive(b"") is None
    assert srv.receive(b"") is None


@default_parametrize
def test_big_unencrypted(transport_cls: type[BaseTransport], transport_obf: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transport_cls, transport_obf=transport_obf)

    message_id = int.from_bytes(urandom(2), "little")
    big_payload = urandom(16 * 1024)
    to_send = cli.send(UnencryptedMessagePacket(message_id, big_payload))
    received = srv.receive(to_send)
    assert isinstance(received, UnencryptedMessagePacket)
    assert received.message_id == message_id
    assert received.message_data == big_payload


@default_parametrize
def test_separate_length(transport_cls: type[BaseTransport], transport_obf: bool):
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
    assert received.message_data == small_payload


@default_parametrize
def test_encrypt_decrypt(transport_cls: type[BaseTransport], transport_obf: bool):
    auth_key = urandom(256)

    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transport_cls, transport_obf=transport_obf)

    to_send_decrypted = DecryptedMessagePacket(
        urandom(8),
        int.from_bytes(urandom(8), "little"),
        int.from_bytes(urandom(8), "little"),
        int.from_bytes(urandom(4), "little"),
        urandom(1024)
    )

    to_send = cli.send(to_send_decrypted.encrypt(auth_key, ConnectionRole.CLIENT))
    received = srv.receive(to_send)
    assert isinstance(received, EncryptedMessagePacket)
    received = received.decrypt(auth_key, ConnectionRole.CLIENT)
    assert isinstance(received, DecryptedMessagePacket)
    assert received.salt == to_send_decrypted.salt
    assert received.session_id == to_send_decrypted.session_id
    assert received.message_id == to_send_decrypted.message_id
    assert received.seq_no == to_send_decrypted.seq_no
    assert received.data == to_send_decrypted.data

    to_send = srv.send(to_send_decrypted.encrypt(auth_key, ConnectionRole.SERVER))
    received = cli.receive(to_send)
    assert isinstance(received, EncryptedMessagePacket)
    received = received.decrypt(auth_key, ConnectionRole.SERVER)
    assert isinstance(received, DecryptedMessagePacket)
    assert received.salt == to_send_decrypted.salt
    assert received.session_id == to_send_decrypted.session_id
    assert received.message_id == to_send_decrypted.message_id
    assert received.seq_no == to_send_decrypted.seq_no
    assert received.data == to_send_decrypted.data


@default_parametrize
def test_has_packet(transport_cls: type[BaseTransport], transport_obf: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transport_cls, transport_obf=transport_obf)

    assert not srv.has_packet()
    assert not cli.has_packet()

    to_send = b""
    packets = []
    for i in range(16):
        packets.append(packet := UnencryptedMessagePacket(i, urandom(16)))
        to_send += cli.send(packet)

    received = srv.receive(to_send)
    assert isinstance(received, UnencryptedMessagePacket)
    assert received.message_id == 0
    assert received.message_data == packets[0].message_data

    for i in range(1, 16):
        assert srv.has_packet()
        received = srv.receive()
        assert isinstance(received, UnencryptedMessagePacket)
        assert received.message_id == i
        assert received.message_data == packets[i].message_data

    assert not srv.has_packet()


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
        def read(self) -> None:
            return None

        def write(self, packet: BasePacket) -> bytes:
            return b""

        def has_packet(self) -> bool:
            return False

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


@default_parametrize
def test_opposite(transport_cls: type[BaseTransport], transport_obf: bool):
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transport_cls, transport_obf=transport_obf)
    opp = cli.opposite()

    assert opp._role == ConnectionRole.SERVER
    assert opp._transport_cls == transport_cls
    assert opp._transport_obf == transport_obf
