from functools import partial
from hashlib import sha256, sha1

try:
    import tgcrypto
except ImportError:  # pragma: no cover
    tgcrypto = None
try:
    import pyaes
except ImportError:  # pragma: no cover
    pyaes = None


if tgcrypto is None and pyaes is None:  # pragma: no cover
    raise ImportWarning(
        "Expected at least one or (tgcrypto, pyaes) to be installed. "
        "You wont be able to use obfuscated transports or mtproto messages encryption/decryption."
    )


if tgcrypto is not None:
    _ctr256_encrypt = tgcrypto.ctr256_encrypt
    _ctr256_decrypt = tgcrypto.ctr256_decrypt
    _ige256_encrypt = tgcrypto.ige256_encrypt
    _ige256_decrypt = tgcrypto.ige256_decrypt
elif pyaes is not None:
    # https://github.com/pyrogram/pyrogram/blob/39694a29497aee87d6ee91155e9b7570b7849aa9/pyrogram/crypto/aes.py#L105
    def ctr(data: bytes, key: bytes, iv: bytearray, state: bytearray) -> bytes:
        cipher = pyaes.AES(key)

        out = bytearray(data)
        chunk = cipher.encrypt(iv)

        for i in range(0, len(data), 16):
            for j in range(0, min(len(data) - i, 16)):
                out[i + j] ^= chunk[state[0]]

                state[0] += 1

                if state[0] >= 16:
                    state[0] = 0

                if state[0] == 0:
                    for k in range(15, -1, -1):
                        try:
                            iv[k] += 1
                            break
                        except ValueError:
                            iv[k] = 0

                    chunk = cipher.encrypt(iv)

        return out


    def xor(a: bytes, b: bytes) -> bytes:
        return int.to_bytes(
            int.from_bytes(a, "big") ^ int.from_bytes(b, "big"),
            len(a),
            "big",
        )


    # https://github.com/pyrogram/pyrogram/blob/39694a29497aee87d6ee91155e9b7570b7849aa9/pyrogram/crypto/aes.py#L85
    def ige(data: bytes, key: bytes, iv: bytes, encrypt: bool) -> bytes:
        cipher = pyaes.AES(key)

        iv_1 = iv[:16]
        iv_2 = iv[16:]

        data = [data[i: i + 16] for i in range(0, len(data), 16)]

        if encrypt:
            for i, chunk in enumerate(data):
                iv_1 = data[i] = xor(cipher.encrypt(xor(chunk, iv_1)), iv_2)
                iv_2 = chunk
        else:
            for i, chunk in enumerate(data):
                iv_2 = data[i] = xor(cipher.decrypt(xor(chunk, iv_2)), iv_1)
                iv_1 = chunk

        return b"".join(data)


    _ctr256_encrypt = ctr
    _ctr256_decrypt = ctr
    _ige256_encrypt = partial(ige, encrypt=True)
    _ige256_decrypt = partial(ige, encrypt=False)
else:  # pragma: no cover
    def _no_crypto_library(*args, **kwargs):
        raise RuntimeError(
            "To use obfuscated transports and mtproto messages encryption/decryption, "
            "you need to install either pyaes or tgcrypto."
        )


    _ctr256_encrypt = _no_crypto_library
    _ctr256_decrypt = _no_crypto_library
    _ige256_encrypt = _no_crypto_library
    _ige256_decrypt = _no_crypto_library


def ctr256_encrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray) -> bytes:
    return _ctr256_encrypt(data, key, iv, state)


def ctr256_decrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray) -> bytes:
    return _ctr256_decrypt(data, key, iv, state)


def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    return _ige256_encrypt(data, key, iv)


def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    return _ige256_decrypt(data, key, iv)


def kdf(auth_key: bytes, msg_key: bytes, from_client: bool) -> tuple:
    # taken from pyrogram, mtproto.py
    x = 0 if from_client else 8

    sha256_a = sha256(msg_key + auth_key[x:x + 36]).digest()
    sha256_b = sha256(auth_key[x + 40:x + 76] + msg_key).digest()  # 76 = 40 + 36

    aes_key = sha256_a[:8] + sha256_b[8:24] + sha256_a[24:32]
    aes_iv = sha256_b[:8] + sha256_a[8:24] + sha256_b[24:32]

    return aes_key, aes_iv


def kdf_v1(auth_key: bytes, msg_key: bytes, from_client: bool) -> tuple:
    x = 0 if from_client else 8

    sha1_a = sha1(msg_key + auth_key[x:x + 32]).digest()
    sha1_b = sha1(auth_key[32 + x:32 + x + 16] + msg_key + auth_key[48 + x:48 + x + 16]).digest()
    sha1_c = sha1(auth_key[64 + x:64 + x + 32] + msg_key).digest()
    sha1_d = sha1(msg_key + auth_key[96 + x:96 + x + 32]).digest()

    aes_key = sha1_a[0:8] + sha1_b[8:8 + 12] + sha1_c[4:4 + 12]
    aes_iv = sha1_a[8:8 + 12] + sha1_b[0:8] + sha1_c[16:16 + 4] + sha1_d[0:8]

    return aes_key, aes_iv


CtrTuple = tuple[bytes, bytes, bytearray]
