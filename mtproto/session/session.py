import bisect
import hashlib
from io import BytesIO
from os import urandom
from time import time

from mtproto import ConnectionRole
from mtproto.session.containers.message import Message
from mtproto.session.containers.msg_container import MsgContainer, MSG_CONTAINER_ID_BYTES
from mtproto.session.containers.msgs_ack import MsgsAck
from mtproto.session.messages import ErrorMessage, UnencryptedMessage, BaseMessage, DataMessage, NeedAuthkey, \
    DataMessages
from mtproto.session.msg_id import MsgId
from mtproto.session.seq_no import SeqNo
from mtproto.transport import transports, Connection
from mtproto.transport.packets import UnencryptedMessagePacket, DecryptedMessagePacket, ErrorPacket, \
    EncryptedMessagePacket
from mtproto.transport.transports.base_transport import BaseTransport
from mtproto.utils import Long, Int

_STRICTLRY_NOT_CONTENT_RELATED = {
    Int.write(0x62d6b459, False),  # MsgsAck
    Int.write(0x73f1f8dc, False),  # MsgContainer
    Int.write(0x3072cfa1, False),  # GzipPacked
}
_STRICTLRY_CONTENT_RELATED = Int.write(0xf35c6d01, False)  # RpcResult


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

            # TODO: ignore BindTempAuthKey
            if packet.salt != self._salt:
                if self._role is ConnectionRole.SERVER:
                    ...  # TODO: send BadServerSalt
                else:
                    # idk, just ignore message?
                    return None

            if packet.session_id != self._session_id:
                if self._role is ConnectionRole.SERVER:
                    self._session_id = packet.session_id
                    ...  # TODO: send NewSessionCreated
                else:
                    return None

            if self._role is ConnectionRole.SERVER:
                if packet.message_id % 4 != 0:
                    # 18: incorrect two lower order msg_id bits
                    #  (the server expects client message msg_id to be divisible by 4)
                    ...  # TODO: BadMsgNotification
                    return None
                elif (packet.message_id >> 32) < (time() - 300):
                    # 16: msg_id too low
                    ...  # TODO: BadMsgNotification
                    return None
                elif (packet.message_id >> 32) > (time() + 30):
                    # 17: msg_id too high
                    ...  # TODO: BadMsgNotification
                    return None
                elif (packet.seq_no & 1) == 1 and packet.data[:4] in _STRICTLRY_NOT_CONTENT_RELATED:
                    # 34: an even msg_seqno expected (irrelevant message), but odd received
                    ...  # TODO: BadMsgNotification
                    return None
                elif (packet.seq_no & 1) == 0 and packet.data[:4] == _STRICTLRY_CONTENT_RELATED:
                    # 35: odd msg_seqno expected (relevant message), but even received
                    ...  # TODO: BadMsgNotification
                    return None

            elif self._role is ConnectionRole.CLIENT:
                if packet.message_id % 4 not in (1, 3):
                    # server message identifiers modulo 4 yield 1 if the message is a response to a client message,
                    #  and 3 otherwise
                    return None
                elif (packet.message_id >> 32) < (time() - 300):
                    # msg_id too low
                    return None
                elif (packet.message_id >> 32) > (time() + 30):
                    # msg_id too high
                    return None

            if not packet.data.startswith(MSG_CONTAINER_ID_BYTES):
                return DataMessage(packet.data)

            container = MsgContainer.read(BytesIO(packet.data))
            result = DataMessages([])

            for message in container.messages:
                if self._role is ConnectionRole.CLIENT and message.seq_no & 1:
                    self.ack_msg_id(message.message_id)
                result.messages.append(DataMessage(message.body))

            return result

        raise ValueError(f"Unknown packet: {packet!r}")