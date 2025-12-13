import bisect
import hashlib
from collections import deque
from io import BytesIO
from os import urandom
from time import time

from mtproto import ConnectionRole
from mtproto.session.service_messages.bad_msg_notification import BadMsgNotification
from mtproto.session.service_messages.bad_server_salt import BadServerSalt
from mtproto.session.service_messages.message import Message
from mtproto.session.service_messages.msg_container import MsgContainer
from mtproto.session.service_messages.msgs_ack import MsgsAck
from mtproto.session.service_messages.new_session_created import NewSessionCreated
from mtproto.session.messages import TransportError, UnencryptedData, BaseEvent, Data, NeedAuthkey, NewSession, \
    MessagesAck, UpdateMessageId
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
_RPC_RESULT_CONSTRUCTOR = Int.write(0xf35c6d01, False)  # RpcResult
_MANUALLY_PARSED_CONSTRUCTORS = {
    MsgContainer.__tl_id_bytes__: MsgContainer,
    NewSessionCreated.__tl_id_bytes__: NewSessionCreated,
    BadServerSalt.__tl_id_bytes__: BadServerSalt,
    BadMsgNotification.__tl_id_bytes__: BadMsgNotification,
    MsgsAck.__tl_id_bytes__: MsgsAck,
}

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
        self._need_ack: list[int] = []
        self._queue: list[Message] = []
        self._pending_packet: EncryptedMessagePacket | None = None
        self._received: deque[BaseEvent] = deque()
        self._pending: dict[int, bytes] = {}

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

    def queue(self, data: bytes, content_related: bool = False, response: bool = False) -> int:
        message = Message(
            message_id=self._msg_id.make(response),
            seq_no=self._seq_no.make(content_related),
            body=data,
        )

        self._queue.append(message)
        self._pending[message.message_id] = data
        return message.message_id

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
        if self._auth_key is None:
            raise ValueError("Auth key needs to be set before calling .send()")

        if self._need_ack:
            to_ack = self._need_ack[:4096]
            self._need_ack = self._need_ack[4096:]
            self.queue(MsgsAck(to_ack).write(), False, False)

        if not data and not self._queue:
            return b""

        if self._queue:
            if data:
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

    def send_session_created(self, first_message_id: int) -> None:
        self.queue(NewSessionCreated(
            first_msg_id=first_message_id,
            unique_id=self._session_id,
            server_salt=Long.read_bytes(self._salt),
        ).serialize())

    def _requeue(self, old_msg_id: int, old_seq_no: int) -> None:
        data = self._pending.pop(old_msg_id)
        new_msg_id = self.queue(data, old_seq_no & 1 == 1, False)
        self._received.append(UpdateMessageId(old_msg_id, new_msg_id))

    def _process_received(self, data: bytes, session_id: int, message_id: int) -> BaseEvent | None:
        constructor = data[:4]
        if constructor == _RPC_RESULT_CONSTRUCTOR:
            req_msg_id = Long.read_bytes(data[4:4 + 8])
            self._pending.pop(req_msg_id, None)
        if constructor not in _MANUALLY_PARSED_CONSTRUCTORS:
            return Data(message_id, session_id, data)

        stream = BytesIO(data)
        obj = _MANUALLY_PARSED_CONSTRUCTORS[stream.read(4)].deserialize(stream)

        if isinstance(obj, MsgContainer):
            for message in obj.messages:
                if self._role is ConnectionRole.CLIENT and message.seq_no & 1:
                    self.ack_msg_id(message.message_id)
                if (processed := self._process_received(message.body, session_id, message.message_id)) is not None:
                    self._received.append(processed)
            return None
        elif isinstance(obj, NewSessionCreated):
            self._received.append(NewSession(self._session_id, None, None))
        elif isinstance(obj, BadServerSalt) and self._role is ConnectionRole.CLIENT:
            self.set_salt(obj.new_server_salt)
            if obj.bad_msg_id in self._pending:
                self._requeue(obj.bad_msg_id, obj.bad_msg_seqno)
        elif isinstance(obj, BadMsgNotification):
            if obj.error_code in (16, 17):
                self._requeue(obj.bad_msg_id, obj.bad_msg_seqno)
            # TODO: requeue 34/35?
        elif isinstance(obj, MsgsAck):
            for msg_id in obj.msg_ids:
                self._pending.pop(msg_id, None)
            self._received.append(MessagesAck(obj.msg_ids))
        else:
            raise RuntimeError("Unreachable")

        if self._received:
            return self._received.popleft()

    def _send_bad_msg_notification(self, msg_id: int, msg_seqno: int, error: int) -> None:
        self.queue(
            BadMsgNotification(bad_msg_id=msg_id, bad_msg_seqno=msg_seqno, error_code=error).serialize(),
            response=True,
        )

    def receive(self, data: bytes = b"") -> BaseEvent | None:
        self._conn.data_received(data)

        if self._received:
            return self._received.popleft()

        packet = self._pending_packet or self._conn.receive()
        if packet is None:
            return None

        if isinstance(packet, ErrorPacket):
            return TransportError(code=packet.error_code)
        elif isinstance(packet, UnencryptedMessagePacket):
            # TODO: does telegram care about message id in not encrypted messages?
            return UnencryptedData(data=packet.message_data)
        elif isinstance(packet, EncryptedMessagePacket):
            if packet.auth_key_id != self._auth_key_id:
                self._pending_packet = packet
                return NeedAuthkey(packet.auth_key_id)

            packet = packet.decrypt(self._auth_key, ConnectionRole.opposite(self._role))

            # TODO: ignore BindTempAuthKey
            if packet.salt != self._salt:
                if self._role is ConnectionRole.SERVER:
                    self.queue(
                        BadServerSalt(
                            bad_msg_id=packet.message_id,
                            bad_msg_seqno=packet.seq_no,
                            error_code=48,
                            new_server_salt=Long.read_bytes(self._salt),
                        ).serialize(),
                        response=True,
                    )
                    return None
                else:
                    # idk, just ignore message?
                    return None

            if packet.session_id != self._session_id:
                if self._role is ConnectionRole.SERVER:
                    self._received.append(NewSession(packet.session_id, self._session_id or None, packet.message_id))
                    self._session_id = packet.session_id
                else:
                    return None

            if self._role is ConnectionRole.SERVER:
                if packet.message_id % 4 != 0:
                    # 18: incorrect two lower order msg_id bits
                    #  (the server expects client message msg_id to be divisible by 4)
                    return self._send_bad_msg_notification(packet.message_id, packet.seq_no, 18)
                elif (packet.message_id >> 32) < (time() - 300):
                    # 16: msg_id too low
                    return self._send_bad_msg_notification(packet.message_id, packet.seq_no, 16)
                elif (packet.message_id >> 32) > (time() + 30):
                    # 17: msg_id too high
                    return self._send_bad_msg_notification(packet.message_id, packet.seq_no, 17)
                elif (packet.seq_no & 1) == 1 and packet.data[:4] in _STRICTLRY_NOT_CONTENT_RELATED:
                    # 34: an even msg_seqno expected (irrelevant message), but odd received
                    return self._send_bad_msg_notification(packet.message_id, packet.seq_no, 34)
                elif (packet.seq_no & 1) == 0 and packet.data[:4] == _RPC_RESULT_CONSTRUCTOR:
                    # 35: odd msg_seqno expected (relevant message), but even received
                    return self._send_bad_msg_notification(packet.message_id, packet.seq_no, 35)

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

            return self._process_received(packet.data, packet.session_id, packet.message_id)

        raise ValueError(f"Unknown packet: {packet!r}")

    def get_pending(self) -> list[tuple[int, bytes]]:
        return list(self._pending.items())

    def clear_pending(self, older_than: int) -> None:
        to_remove = []
        for msg_id in self._pending.keys():
            if (msg_id >> 32) < (time() - older_than):
                to_remove.append(msg_id)

        for msg_id in to_remove:
            del self._pending[msg_id]
