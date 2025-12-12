from os import urandom

import pytest as pt

from mtproto import ConnectionRole
from mtproto.transport.packets import DecryptedMessagePacket
from mtproto.utils import Long, Int


@pt.mark.parametrize("sender_role,v1", [
    (ConnectionRole.SERVER, True),
    (ConnectionRole.SERVER, False),
    (ConnectionRole.CLIENT, True),
    (ConnectionRole.CLIENT, False),
])
def test_encrypt_decrypt(sender_role: ConnectionRole, v1: bool) -> None:
    key = urandom(256)

    initial_message = DecryptedMessagePacket(
        salt=urandom(8),
        session_id=Long.read_bytes(urandom(8)),
        message_id=Long.read_bytes(urandom(8)),
        seq_no=Int.read_bytes(urandom(4)),
        data=urandom(512),
    )

    encrypted = initial_message.encrypt(key, sender_role, v1)
    decrypted = encrypted.decrypt(key, sender_role, v1)

    assert initial_message.salt == decrypted.salt
    assert initial_message.session_id == decrypted.session_id
    assert initial_message.message_id == decrypted.message_id
    assert initial_message.seq_no == decrypted.seq_no
    assert initial_message.data == decrypted.data
