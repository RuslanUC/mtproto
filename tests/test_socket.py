import socket
from os import urandom
from time import time

import pytest as pt

from mtproto.enums import ConnectionRole
from mtproto.session import Session
from mtproto.session.messages import UnencryptedData
from mtproto.transport import Connection, transports
from mtproto.transport.packets import UnencryptedMessagePacket
from mtproto.transport.transports.base_transport import BaseTransport
from mtproto.transport.transports.http import HttpTransportParamHost

default_parameters_no_full = [
    (transports.AbridgedTransport, False,),
    (transports.AbridgedTransport, True,),
    (transports.IntermediateTransport, False,),
    (transports.IntermediateTransport, True,),
    (transports.PaddedIntermediateTransport, False,),
    (transports.PaddedIntermediateTransport, True,),
    (transports.FullTransport, False,),
    (transports.HttpTransport, False,),
]
default_parametrize = pt.mark.parametrize("transport_cls,transport_obf", default_parameters_no_full)


class MsgId:
    last_time = 0
    offset = 0

    @classmethod
    def create(cls) -> int:
        now = int(time())
        cls.offset = (cls.offset + 4) if now == cls.last_time else 0
        msg_id = (now * 2 ** 32) + cls.offset
        cls.last_time = now

        return msg_id


@default_parametrize
def test_socket_telegram(transport_cls: type[BaseTransport], transport_obf: bool):
    cli = Connection(ConnectionRole.CLIENT, transport=transport_cls, obfuscated=transport_obf)
    if issubclass(transport_cls, transports.HttpTransport):
        cli.set_transport_param(HttpTransportParamHost(host="149.154.167.40"))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("149.154.167.40", 443))

    to_send = cli.send(UnencryptedMessagePacket(
        MsgId.create(),
        b"\xbe\x7e\x8e\xf1"[::-1] + urandom(16)  # req_pq_multi#be7e8ef1 nonce:int128
    ))
    sock.send(to_send)
    #print(f"Sent: {to_send}")
    while True:
        sock_recv = sock.recv(1024)
        cli.data_received(sock_recv)
        recv = cli.next_event()
        if recv is None:
            #print(f"Received partial data from socket ({sock_recv}), reading more...")
            continue
        #print(f"Received: {recv}")
        assert isinstance(recv, UnencryptedMessagePacket)
        assert recv.message_data[:4] == b"\x05\x16\x24\x63"[::-1]

        break

    sock.close()


@default_parametrize
def test_socket_telegram_with_session(transport_cls: type[BaseTransport], transport_obf: bool):
    session = Session(ConnectionRole.CLIENT, transport_cls, transport_obf)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("149.154.167.40", 443))

    to_send = session.send_plain(
        b"\xbe\x7e\x8e\xf1"[::-1] + urandom(16)  # req_pq_multi#be7e8ef1 nonce:int128
    )
    sock.send(to_send)
    print(f"Sent: {to_send}")
    while True:
        sock_recv = sock.recv(1024)
        session.data_received(sock_recv)
        recv = session.next_event()
        if recv is None:
            print(f"Received partial data from socket ({sock_recv}), reading more...")
            continue
        print(f"Received: {recv}")
        assert isinstance(recv, UnencryptedData)
        assert recv.data[:4] == b"\x05\x16\x24\x63"[::-1]

        break

    sock.close()
