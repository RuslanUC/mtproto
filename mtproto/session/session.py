import bisect
import hashlib
from os import urandom

from mtproto import ConnectionRole
from mtproto.session.containers.message import Message
from mtproto.session.containers.msg_container import MsgContainer
from mtproto.session.containers.msgs_ack import MsgsAck
from mtproto.session.messages import ErrorMessage, UnencryptedMessage, BaseMessage, DataMessage, NeedAuthkey
from mtproto.session.msg_id import MsgId
from mtproto.session.seq_no import SeqNo
from mtproto.transport import transports, Connection
from mtproto.transport.packets import UnencryptedMessagePacket, DecryptedMessagePacket, ErrorPacket, \
    EncryptedMessagePacket
from mtproto.transport.transports.base_transport import BaseTransport
from mtproto.utils import Long


class Session:
    def __init__(
            self,
            role: ConnectionRole,
            transport: type[BaseTransport] = transports.AbridgedTransport,
            obfuscated: bool = False,
            auth_key: bytes | None = None,
            salt: int | bytes | None = None,
    ) -> None:
        self._role = role
        self._conn = Connection(role, transport, obfuscated)
        self._auth_key: bytes | None = None
        self._auth_key_id: int | None = None
        self._salt: bytes | None = None
        self._seq_no = SeqNo()
        self._msg_id = MsgId(role)
        self._session_id: int = Long.read_bytes(urandom(8)) if role is ConnectionRole.CLIENT else 0
        self._need_ack = []
        self._queue = []
        self._pending_packet: EncryptedMessagePacket | None = None

        if auth_key is not None:
            self.set_auth_key(auth_key)
        if salt is not None:
            self.set_salt(salt)

    def set_auth_key(self, auth_key: bytes) -> None:
        if len(auth_key) != 256:
            raise ValueError("Invalid auth key provided: need to be exactly 256 bytes")
        self._auth_key = auth_key
        self._auth_key_id = Long.read_bytes(hashlib.sha1(auth_key).digest()[-8:])

    def set_salt(self, salt: int | bytes) -> None:
        if isinstance(salt, int):
            self._salt = Long.write(salt)
            return
        if len(salt) != 8:
            raise ValueError("Invalid salt: needs to be exactly 8 bytes")
        self._salt = salt

    def queue(self, data: bytes, content_related: bool = False, response: bool = False) -> None:
        self._queue.append(Message(
            message_id=self._msg_id.make(response),
            seq_no=self._seq_no.make(content_related),
            body=data,
        ))

    def ack_msg_id(self, msg_id: int) -> None:
        if self._need_ack:
            idx = bisect.bisect_left(self._need_ack, msg_id)
            if self._need_ack[idx] == msg_id:
                return
            self._need_ack.insert(idx, msg_id)
        else:
            self._need_ack.append(msg_id)

    def send(
            self, data: bytes | None, content_related: bool = False, response: bool = False,
    ) -> bytes:
        if self._need_ack:
            to_ack = self._need_ack[:4096]
            self._need_ack = self._need_ack[4096:]
            self.queue(MsgsAck(to_ack).write(), False, False)

        if self._queue:
            self.queue(data, content_related, response)
            data = MsgContainer(self._queue).write()
            self._queue.clear()
            response = False
            content_related = False

        return self._conn.send(
            DecryptedMessagePacket(
                salt=self._salt,
                session_id=self._session_id,
                message_id=self._msg_id.make(response),
                seq_no=self._seq_no.make(content_related),
                data=data,
            ).encrypt(self._auth_key, self._role)
        )

    def send_plain(self, data: bytes) -> bytes:
        return self._conn.send(UnencryptedMessagePacket(
            message_id=self._msg_id.make(True),
            message_data=data,
        ))

    def receive(self, data: bytes = b"") -> BaseMessage | None:
        self._conn.data_received(data)
        packet = self._pending_packet or self._conn.receive()
        if packet is None:
            return None

        if isinstance(packet, ErrorPacket):
            return ErrorMessage(code=packet.error_code)
        elif isinstance(packet, UnencryptedMessagePacket):
            # TODO: does telegram care about message id in not encrypted messages?
            return UnencryptedMessage(data=packet.message_data)
        elif isinstance(packet, EncryptedMessagePacket):
            if packet.auth_key_id != self._auth_key_id:
                self._pending_packet = packet
                return NeedAuthkey(packet.auth_key_id)
            packet = packet.decrypt(self._auth_key, ConnectionRole.opposite(self._role))
            # TODO: check salt, session_id, message_id, seq_no
            return DataMessage(packet.data)

        raise ValueError(f"Unknown packet: {packet!r}")