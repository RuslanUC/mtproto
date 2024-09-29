try:
    import tgcrypto
except ImportError:
    tgcrypto = None
try:
    import pyaes
except ImportError:
    pyaes = None


if tgcrypto is None and pyaes is None:
    raise ImportError("Expected at least one or (tgcrypto, pyaes) to be installed.")


if tgcrypto is not None:
    _ctr256_encrypt = tgcrypto.ctr256_encrypt
    _ctr256_decrypt = tgcrypto.ctr256_decrypt
elif pyaes is not None:
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


    _ctr256_encrypt = ctr
    _ctr256_decrypt = ctr


def ctr256_encrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray = None) -> bytes:
    return _ctr256_encrypt(data, key, iv, state or bytearray(1))


def ctr256_decrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray = None) -> bytes:
    return _ctr256_decrypt(data, key, iv, state or bytearray(1))


def xor(a: bytes, b: bytes) -> bytes:
    return int.to_bytes(
        int.from_bytes(a, "big") ^ int.from_bytes(b, "big"),
        len(a),
        "big",
    )


CtrTuple = tuple[bytes, bytes, bytearray]
