import bisect
import hashlib
import logging
from collections import deque
from io import BytesIO
from os import urandom
from time import time

from mtproto import ConnectionRole
from mtproto.session.service_messages.bad_msg_notification import BadMsgNotification
from mtproto.session.service_messages.bad_server_salt import BadServerSalt
from mtproto.session.service_messages.future_salts import FutureSalts
from mtproto.session.service_messages.get_future_salts import GetFutureSalts
from mtproto.session.service_messages.http_wait import HttpWait
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
    MsgsAck.__tl_id_bytes__,
    MsgContainer.__tl_id_bytes__,
    Int.write(0x3072cfa1, False),  # GzipPacked
}
_RPC_RESULT_CONSTRUCTOR = Int.write(0xf35c6d01, False)
_MANUALLY_PARSED_CONSTRUCTORS = {
    MsgContainer.__tl_id_bytes__: MsgContainer,
    NewSessionCreated.__tl_id_bytes__: NewSessionCreated,
    BadServerSalt.__tl_id_bytes__: BadServerSalt,
    BadMsgNotification.__tl_id_bytes__: BadMsgNotification,
    MsgsAck.__tl_id_bytes__: MsgsAck,
}
# I have no idea what actual packet size limit is, but it is around 1 megabyte
_PACKET_SIZE_LIMIT = 1000 * 1000
_EMPTY_CONTAINER_SIZE = len(MsgContainer([]).write())
_EMPTY_MESSAGE_SIZE = len(Message(0, 0, b"").write())
# Two times smaller than value in docs
_CONTAINER_SIZE_LIMIT = 512
# Two times smaller than value in docs
_ACK_SIZE_LIMIT = 4096

log = logging.getLogger(__name__)


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
        self._salts: list[tuple[bytes, int]] = []
        self._seq_no = SeqNo()
        self._msg_id = MsgId(role)
        self._session_id: int = Long.read_bytes(urandom(8)) if role is ConnectionRole.CLIENT else 0
        self._need_ack: list[int] = []
        self._queue: deque[Message] = deque()
        self._queue_plain: deque[bytes] = deque()
        self._pending_packet: EncryptedMessagePacket | None = None
        self._received: deque[BaseEvent] = deque()
        self._pending: dict[int, bytes] = {}
        self._pending_containers: dict[int, list[tuple[int, bool]]] = {}
        self._future_salts_req: int | None = None
        self._salts_fetched_at: int = 0
        self._is_http = issubclass(transport, transports.HttpTransport)

        if auth_key is not None:
            self.set_auth_key(auth_key)
        if salt is not None:
            self.set_salts([
                (salt, int(time() - 30 * 60)),
            ])
        else:
            self.set_salts([(0, 0)])

    def set_auth_key(self, auth_key: bytes) -> None:
        if len(auth_key) != 256:
            raise ValueError("Invalid auth key provided: need to be exactly 256 bytes")
        self._auth_key = auth_key
        self._auth_key_id = Long.read_bytes(hashlib.sha1(auth_key).digest()[-8:])

    def set_salts(self, salts: list[tuple[int | bytes, int]]) -> None:
        self._salts.clear()
        for salt, valid_from in salts:
            if isinstance(salt, int):
                self._salts.append((Long.write(salt), valid_from))
                continue
            if len(salt) != 8:
                raise ValueError("Invalid salt: needs to be exactly 8 bytes")
            self._salts.append((salt, valid_from))

        self._salts.sort(key=lambda s: s[1])

    def add_salt(self, salt: int | bytes, valid_from: int) -> None:
        if isinstance(salt, int):
            salt = Long.write(salt)

        if not self._salts:
            self._salts.append((salt, valid_from))
            return

        add_idx = bisect.bisect_left(self._salts, valid_from, key=lambda s: s[1])
        if add_idx < len(self._salts) and self._salts[add_idx][1] == valid_from:
            self._salts[add_idx] = salt, valid_from
        else:
            self._salts.insert(add_idx, (salt, valid_from))

    def clear_salts(self) -> None:
        older_than = time() - 60 * 60
        remove_salts = bisect.bisect_left(self._salts, older_than, key=lambda s: s[1])
        while remove_salts:
            self._salts.pop(0)
            remove_salts -= 1

    def check_salt(self, salt: int | bytes) -> bool:
        lo = bisect.bisect_left(self._salts, time() - 60 * 60, key=lambda s: s[1])
        hi = bisect.bisect_right(self._salts, time(), key=lambda s: s[1])

        salt = Long.write(salt) if isinstance(salt, int) else salt
        for i in range(lo, hi):
            if self._salts[i][0] == salt:
                return True

        return False

    def get_salt(self) -> bytes:
        if len(self._salts) == 1:
            log.debug(f"Using only salt {self._salts[0][0]!r} (valid since {self._salts[0][1]})")
            return self._salts[0][0]
        idx = bisect.bisect_left(self._salts, time(), key=lambda s: s[1])
        if idx > 0:
            idx -= 1
        log.debug(f"Using salt {self._salts[idx][0]!r} (valid since {self._salts[idx][1]})")
        return self._salts[idx][0]

    def queue(
            self, data: bytes, content_related: bool = False, response: bool = False,
            *, _left: bool = False, _msg_id: int | None = None, _add_pending: bool = True,
    ) -> int:
        message = Message(
            message_id=_msg_id if _msg_id is not None else self._msg_id.make(response),
            seq_no=self._seq_no.make(content_related),
            body=data,
        )

        if _left:
            self._queue.appendleft(message)
        else:
            self._queue.append(message)

        if _add_pending:
            self._pending[message.message_id] = data

        return message.message_id

    def ack_msg_id(self, msg_id: int) -> None:
        if self._need_ack:
            idx = bisect.bisect_left(self._need_ack, msg_id)
            if idx < len(self._need_ack) and self._need_ack[idx] == msg_id:
                return
            self._need_ack.insert(idx, msg_id)
        else:
            self._need_ack.append(msg_id)

    def send_protocol_id(self) -> bytes:
        if self._role is ConnectionRole.SERVER:
            return b""
        return self._conn.send(None)

    def _make_container(self, message_id: int) -> bytes:
        container = MsgContainer([])
        ids = []

        self._pending_containers[message_id] = ids

        total_size = _EMPTY_CONTAINER_SIZE
        while total_size < _PACKET_SIZE_LIMIT and self._queue and len(container.messages) < _CONTAINER_SIZE_LIMIT:
            message_size = len(self._queue[0].body) + _EMPTY_MESSAGE_SIZE
            if total_size + message_size > _PACKET_SIZE_LIMIT and container.messages:
                break
            log.debug(f"Add message of size {message_size} to container {message_id}")
            total_size += message_size
            message = self._queue.popleft()
            container.messages.append(message)
            ids.append((message.message_id, message.seq_no & 1 == 1))
            self._pending_containers[message.message_id] = ids

        log.debug(f"Container with {len(container.messages)} messages will be sent as {message_id}")
        return container.write()

    def send(
            self, data: bytes | None, content_related: bool = False, response: bool = False,
    ) -> bytes:
        if self._auth_key is None:
            raise ValueError("Auth key needs to be set before calling .send()")

        if not self._conn.transport_send_ready():
            log.info("Transport is not ready to send data, queueing...")
            if data:
                self.queue(data, content_related, response)
            return b""

        if self._need_ack:
            to_ack = self._need_ack[:_ACK_SIZE_LIMIT]
            self._need_ack = self._need_ack[_ACK_SIZE_LIMIT:]
            self.queue(MsgsAck(to_ack).write(), False, False)
            log.debug(f"Will ack messages: {to_ack!r}...")

        self._fetch_future_salts_maybe()

        if not self._queue and not data:
            return b""

        if self._role is ConnectionRole.CLIENT and self._is_http:
            self.queue(HttpWait(max_delay=0, wait_after=0, max_wait=250).write(), _left=True, _add_pending=False)

        if self._queue:
            if data:
                self.queue(data, content_related, response)

            message_id = self._msg_id.make(False)
            data = self._make_container(message_id)

            content_related = False
        elif data:
            message_id = self._msg_id.make(response)
            log.debug(f"Message will be sent as {message_id}")
            self._pending[message_id] = data
        else:
            return b""

        log.debug(f"Will send {len(data)} bytes")

        return self._conn.send(
            DecryptedMessagePacket(
                salt=self.get_salt(),
                session_id=self._session_id,
                message_id=message_id,
                seq_no=self._seq_no.make(content_related),
                data=data,
            ).encrypt(self._auth_key, self._role)
        )

    def send_plain(self, data: bytes, queue: bool = False) -> bytes:
        if not self._conn.transport_send_ready() and queue:
            if data:
                self._queue_plain.append(data)
            return b""

        to_send = b""

        for queued in self._queue_plain:
            to_send += self._conn.send(UnencryptedMessagePacket(
                message_id=self._msg_id.make(True),
                message_data=queued,
            ))

        self._queue_plain.clear()

        if data:
            to_send += self._conn.send(UnencryptedMessagePacket(
                message_id=self._msg_id.make(True),
                message_data=data,
            ))

        return to_send

    def send_session_created(self, first_message_id: int) -> None:
        self.queue(NewSessionCreated(
            first_msg_id=first_message_id,
            unique_id=self._session_id,
            server_salt=Long.read_bytes(self.get_salt()),
        ).serialize())

    def _requeue(self, old_msg_id: int, old_seq_no: int, left: bool = False, preserve_msg_id: bool = False) -> None:
        data = self._pending.pop(old_msg_id, None)
        if data is None:
            return
        new_msg_id = self.queue(
            data=data,
            content_related=old_seq_no & 1 == 1,
            response=False,
            _left=left,
            _msg_id=old_msg_id if preserve_msg_id else None,
        )
        if not preserve_msg_id:
            self._received.append(UpdateMessageId(old_msg_id, new_msg_id))
        if old_msg_id == self._future_salts_req and not preserve_msg_id:
            self._future_salts_req = new_msg_id
        log.debug(f"Requeue-d message {old_msg_id} as {new_msg_id}")

    def _requeue_container(self, old_msg_id: int) -> None:
        message_ids = self._pending_containers.pop(old_msg_id)
        for message_id, content_related in reversed(message_ids):
            self._pending_containers.pop(message_id, None)
            self._requeue(message_id, content_related, True)
        log.debug(f"Requeue-d all messages in container {old_msg_id}")

    def _fetch_future_salts_maybe(self, force: bool = False) -> None:
        if self._role is ConnectionRole.SERVER:
            return
        if self._future_salts_req is not None and (time() - self._salts_fetched_at) < 1 * 60:
            return
        elif not force and (time() - self._salts_fetched_at) < 5 * 60:
            return

        log.debug("Requesting future salts")

        if self._future_salts_req is not None:
            self._pending.pop(self._future_salts_req, None)

        self._future_salts_req = self.queue(GetFutureSalts(24).write(), True)
        self._salts_fetched_at = time()

    def _process_ack(self, message_id: int) -> None:
        self._pending.pop(message_id, None)
        container = self._pending_containers.pop(message_id, None)
        if container is None:
            return
        for msg_id, _ in container:
            self._pending_containers.pop(msg_id, None)

    def _process_received(self, data: bytes, session_id: int, message_id: int) -> BaseEvent | None:
        constructor = data[:4]
        if constructor == _RPC_RESULT_CONSTRUCTOR:
            req_msg_id = Long.read_bytes(data[4:4 + 8])
            self._process_ack(req_msg_id)
        elif constructor == FutureSalts.__tl_id_bytes__ and Long.read_bytes(data[4:4 + 8]) == self._future_salts_req:
            future_salts = FutureSalts.read(BytesIO(data))
            for salt in future_salts.salts:
                self.add_salt(salt.salt, salt.valid_since)

            self._future_salts_req = None
            self._salts_fetched_at = time()
            return None

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
        elif isinstance(obj, NewSessionCreated):
            self._received.append(NewSession(self._session_id, None, None))
        elif isinstance(obj, BadServerSalt) and self._role is ConnectionRole.CLIENT:
            log.debug(f"Got BadServerSalt for message {obj.bad_msg_id}")
            self.set_salts([
                (obj.new_server_salt, int(time() - 30 * 60)),
            ])
            if obj.bad_msg_id in self._pending:
                self._requeue(obj.bad_msg_id, obj.bad_msg_seqno)
            elif obj.bad_msg_id in self._pending_containers:
                self._requeue_container(obj.bad_msg_id)
            else:
                log.warning(f"Got BadServerSalt for unknown message {obj.bad_msg_id}")
            self._fetch_future_salts_maybe(True)
        elif isinstance(obj, BadMsgNotification) and self._role is ConnectionRole.CLIENT:
            log.debug(f"Got BadMsgNotification for message {obj.bad_msg_id}")
            if obj.error_code in (16, 17):
                self._requeue(obj.bad_msg_id, obj.bad_msg_seqno)
            # TODO: requeue 34/35?
        elif isinstance(obj, MsgsAck):
            for msg_id in obj.msg_ids:
                self._process_ack(msg_id)
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

    def data_received(self, data: bytes) -> None:
        self._conn.data_received(data)

    def next_event(self) -> BaseEvent | None:
        if self._received:
            return self._received.popleft()

        packet = self._pending_packet or self._conn.next_event()
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
            if self._role is ConnectionRole.SERVER and not self.check_salt(packet.salt):
                self.queue(
                    BadServerSalt(
                        bad_msg_id=packet.message_id,
                        bad_msg_seqno=packet.seq_no,
                        error_code=48,
                        new_server_salt=Long.read_bytes(self.get_salt()),
                    ).serialize(),
                    response=True,
                )
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
