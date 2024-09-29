from mtproto import ConnectionRole, Connection, transports
from mtproto.packets import UnencryptedMessagePacket, QuickAckPacket, ErrorPacket, EncryptedMessagePacket


def send_recv_some_values(srv: Connection, cli: Connection, quick_ack: bool = True) -> None:
    to_send = cli.send(UnencryptedMessagePacket(123, b"test"))
    received = srv.receive(to_send)
    assert isinstance(received, UnencryptedMessagePacket)
    assert received.message_id == 123
    assert received.message_data == b"test"

    if quick_ack:
        to_send = srv.send(QuickAckPacket(b"\x8012\x80"))
        received = cli.receive(to_send)
        assert isinstance(received, QuickAckPacket)
        assert received.token == b"\x8012\x80"

    to_send = srv.send(ErrorPacket(400))
    received = cli.receive(to_send)
    assert isinstance(received, ErrorPacket)
    assert received.error_code == 400

    #to_send = cli.send(EncryptedMessagePacket(123456, b"\xff" * 16, b"test_encrypted"))
    #received = srv.receive(to_send)
    #assert isinstance(received, EncryptedMessagePacket)
    #assert received.auth_key_id == 123456
    #assert received.message_key == b"\xff" * 16
    #assert received.encrypted_data == b"test_encrypted"


def test_abridged_noobf() -> None:
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transports.AbridgedTransport, transport_obf=False)

    send_recv_some_values(srv, cli)


def test_abridged_obf() -> None:
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transports.AbridgedTransport, transport_obf=True)

    send_recv_some_values(srv, cli)


def test_intermediate_noobf() -> None:
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transports.IntermediateTransport, transport_obf=False)

    send_recv_some_values(srv, cli)


def test_intermediate_obf() -> None:
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transports.IntermediateTransport, transport_obf=True)

    send_recv_some_values(srv, cli)


def test_paddedintermediate_noobf() -> None:
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transports.PaddedIntermediateTransport, transport_obf=False)

    send_recv_some_values(srv, cli)


def test_paddedintermediate_obf() -> None:
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transports.PaddedIntermediateTransport, transport_obf=True)

    send_recv_some_values(srv, cli)


def test_full_noobf() -> None:
    srv = Connection(ConnectionRole.SERVER)
    cli = Connection(ConnectionRole.CLIENT, transport_cls=transports.FullTransport, transport_obf=False)

    send_recv_some_values(srv, cli, False)

