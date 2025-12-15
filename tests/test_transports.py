from os import urandom
from random import randint
from zlib import crc32

from mtproto.enums import ConnectionRole
from mtproto.transport import Connection, transports
from mtproto.transport.packets import UnencryptedMessagePacket, QuickAckPacket, ErrorPacket, EncryptedMessagePacket, \
    BasePacket, DecryptedMessagePacket
import pytest as pt

from mtproto.transport.transports.base_transport import BaseTransport


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

    srv.data_received(b"")
    assert srv.next_event() is None
    with pt.raises(ValueError):
        cli.next_event()


@default_parametrize
def test_small_unencrypted(transport_cls: type[BaseTransport], transport_obf: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport=transport_cls, obfuscated=transport_obf)

    message_id = int.from_bytes(urandom(2), "little")
    small_payload = urandom(16)
    to_send = cli.send(UnencryptedMessagePacket(message_id, small_payload))
    srv.data_received(to_send)
    received = srv.next_event()
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
    cli = Connection(ConnectionRole.CLIENT, transport=transport_cls, obfuscated=transport_obf)

    # Client MUST send something first
    srv.data_received(cli.send(UnencryptedMessagePacket(0, b"1234")))
    assert srv.next_event() is not None

    if quick_ack:
        token = b"".join([b"\x80", urandom(2), b"\x80"])
        to_send = srv.send(QuickAckPacket(token))
        cli.data_received(to_send)
        received = cli.next_event()
        assert isinstance(received, QuickAckPacket)
        assert received.token == token


@default_parametrize
def test_error(transport_cls: type[BaseTransport], transport_obf: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport=transport_cls, obfuscated=transport_obf)

    # Client MUST send something first
    srv.data_received(cli.send(UnencryptedMessagePacket(0, b"1234")))
    assert srv.next_event() is not None

    error_code = randint(300, 599)
    to_send = srv.send(ErrorPacket(error_code))
    cli.data_received(to_send)
    received = cli.next_event()
    assert isinstance(received, ErrorPacket)
    assert received.error_code == error_code


@default_parametrize
def test_encrypted(transport_cls: type[BaseTransport], transport_obf: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport=transport_cls, obfuscated=transport_obf)

    key_id = int.from_bytes(urandom(4), "little")
    msg_id = urandom(16)
    data = urandom(32)
    to_send = cli.send(EncryptedMessagePacket(key_id, msg_id, data))
    srv.data_received(to_send)
    received = srv.next_event()
    assert isinstance(received, EncryptedMessagePacket)
    assert received.auth_key_id == key_id
    assert received.message_key == msg_id
    assert received.encrypted_data == data


@default_parametrize
def test_receive_empty(transport_cls: type[BaseTransport], transport_obf: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport=transport_cls, obfuscated=transport_obf)

    # Client MUST send something first
    srv.data_received(cli.send(UnencryptedMessagePacket(0, b"1234")))
    assert srv.next_event() is not None

    assert cli.next_event() is None
    assert srv.next_event() is None


@default_parametrize
def test_big_unencrypted(transport_cls: type[BaseTransport], transport_obf: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport=transport_cls, obfuscated=transport_obf)

    message_id = int.from_bytes(urandom(2), "little")
    big_payload = urandom(16 * 1024)
    to_send = cli.send(UnencryptedMessagePacket(message_id, big_payload))
    srv.data_received(to_send)
    received = srv.next_event()
    assert isinstance(received, UnencryptedMessagePacket)
    assert received.message_id == message_id
    assert received.message_data == big_payload


@default_parametrize
def test_separate_length(transport_cls: type[BaseTransport], transport_obf: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport=transport_cls, obfuscated=transport_obf)

    message_id = int.from_bytes(urandom(2), "little")
    small_payload = urandom(16)
    to_send = cli.send(UnencryptedMessagePacket(message_id, small_payload))
    srv.data_received(to_send[:1])
    assert srv.next_event() is None
    srv.data_received(to_send[1:4])
    assert srv.next_event() is None
    srv.data_received(to_send[4:])
    received = srv.next_event()
    assert isinstance(received, UnencryptedMessagePacket)
    assert received.message_id == message_id
    assert received.message_data == small_payload


@default_parametrize
def test_encrypt_decrypt(transport_cls: type[BaseTransport], transport_obf: bool):
    auth_key = urandom(256)

    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport=transport_cls, obfuscated=transport_obf)

    to_send_decrypted = DecryptedMessagePacket(
        urandom(8),
        int.from_bytes(urandom(8), "little") >> 1,
        int.from_bytes(urandom(4), "little") >> 1,
        int.from_bytes(urandom(4), "little") >> 1,
        urandom(1024)
    )

    to_send = cli.send(to_send_decrypted.encrypt(auth_key, ConnectionRole.CLIENT))
    srv.data_received(to_send)
    received = srv.next_event()
    assert isinstance(received, EncryptedMessagePacket)
    received = received.decrypt(auth_key, ConnectionRole.CLIENT)
    assert isinstance(received, DecryptedMessagePacket)
    assert received.salt == to_send_decrypted.salt
    assert received.session_id == to_send_decrypted.session_id
    assert received.message_id == to_send_decrypted.message_id
    assert received.seq_no == to_send_decrypted.seq_no
    assert received.data == to_send_decrypted.data

    to_send = srv.send(to_send_decrypted.encrypt(auth_key, ConnectionRole.SERVER))
    cli.data_received(to_send)
    received = cli.next_event()
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
    cli = Connection(ConnectionRole.CLIENT, transport=transport_cls, obfuscated=transport_obf)

    assert not srv.has_packet()
    assert not cli.has_packet()

    to_send = b""
    packets = []
    for i in range(16):
        packets.append(packet := UnencryptedMessagePacket(i, urandom(16)))
        to_send += cli.send(packet)

    srv.data_received(to_send)
    received = srv.next_event()
    assert isinstance(received, UnencryptedMessagePacket)
    assert received.message_id == 0
    assert received.message_data == packets[0].message_data

    for i in range(1, 16):
        assert srv.has_packet()
        received = srv.next_event()
        assert isinstance(received, UnencryptedMessagePacket)
        assert received.message_id == i
        assert received.message_data == packets[i].message_data

    assert not srv.has_packet()


def test_full_obf_raises() -> None:
    with pt.raises(ValueError):
        cli = Connection(ConnectionRole.CLIENT, transport=transports.FullTransport, obfuscated=True)
        cli.send(ErrorPacket(400))


def test_full_quick_ack_raises() -> None:
    with pt.raises(ValueError):
        cli = Connection(ConnectionRole.CLIENT, transport=transports.FullTransport, obfuscated=False)
        cli.send(QuickAckPacket(b"\x80" * 4))


def test_invalid_transport() -> None:
    class NotSupportedTransport(BaseTransport):
        SUPPORTS_OBFUSCATION = True

        def read(self) -> None:
            return None

        def write(self, packet: BasePacket) -> bytes:
            return b""

        def has_packet(self) -> bool:
            return False

        def peek(self) -> BasePacket | None:
            return None

    with pt.raises(ValueError):
        cli = Connection(ConnectionRole.CLIENT, transport=NotSupportedTransport, obfuscated=True)
        cli.send(ErrorPacket(400))


def test_full_invalid_seq_no() -> None:
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport=transports.FullTransport, obfuscated=False)
    to_send = cli.send(ErrorPacket(400))
    to_send = bytearray(to_send)
    to_send[4:8] = (int.from_bytes(to_send[4:8], "little") + 123).to_bytes(4, "little")
    to_send[-4:] = crc32(to_send[:-4]).to_bytes(4, byteorder="little")
    to_send = bytes(to_send)
    srv.data_received(to_send)
    assert srv.next_event() is None


def test_full_invalid_crc() -> None:
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport=transports.FullTransport, obfuscated=False)
    to_send = cli.send(ErrorPacket(400))
    to_send = bytearray(to_send)
    to_send[-4:] = (int.from_bytes(to_send[-4:], "little") + 1).to_bytes(4, "little")
    srv.data_received(to_send)
    assert srv.next_event() is None


@default_parametrize
def test_opposite(transport_cls: type[BaseTransport], transport_obf: bool):
    cli = Connection(ConnectionRole.CLIENT, transport=transport_cls, obfuscated=transport_obf)
    opp = cli.opposite()

    assert opp._role == ConnectionRole.SERVER
    assert opp._transport_cls == transport_cls
    assert opp._transport_obf == transport_obf


@default_parametrize
def test_peek_small_unencrypted(transport_cls: type[BaseTransport], transport_obf: bool):
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport=transport_cls, obfuscated=transport_obf)

    message_id_1 = int.from_bytes(urandom(2), "little")
    message_id_2 = int.from_bytes(urandom(2), "little")
    small_payload_1 = urandom(16)
    small_payload_2 = urandom(16)
    srv.data_received(
        cli.send(UnencryptedMessagePacket(message_id_1, small_payload_1))
        + cli.send(UnencryptedMessagePacket(message_id_2, small_payload_2))
    )
    received = srv.next_event()
    assert isinstance(received, UnencryptedMessagePacket)
    assert received.message_id == message_id_1
    assert received.message_data == small_payload_1

    assert srv.has_packet()

    peeked = srv.peek_packet()
    assert isinstance(peeked, UnencryptedMessagePacket)
    assert peeked.message_id == message_id_2
    assert peeked.message_data == small_payload_2

    assert srv.has_packet()

    received_2 = srv.next_event()
    assert isinstance(received_2, UnencryptedMessagePacket)
    assert received_2.message_id == message_id_2
    assert received_2.message_data == small_payload_2

    assert not srv.has_packet()
