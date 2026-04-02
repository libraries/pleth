import hashlib
import pleth.keccak
import random


def test_shake128():
    for _ in range(4):
        m = random.randbytes(random.randint(0, 1024))
        a = pleth.keccak.shake128(bytearray(m), 32)
        b = hashlib.shake_128(m).digest(32)
        assert a == b


def test_shake256():
    for _ in range(4):
        m = random.randbytes(random.randint(0, 1024))
        a = pleth.keccak.shake256(bytearray(m), 32)
        b = hashlib.shake_256(m).digest(32)
        assert a == b


def test_sha3_224():
    for _ in range(4):
        m = random.randbytes(random.randint(0, 1024))
        a = pleth.keccak.sha3_224(bytearray(m))
        b = hashlib.sha3_224(m).digest()
        assert a == b


def test_sha3_256():
    for _ in range(4):
        m = random.randbytes(random.randint(0, 1024))
        a = pleth.keccak.sha3_256(bytearray(m))
        b = hashlib.sha3_256(m).digest()
        assert a == b


def test_sha3_384():
    for _ in range(4):
        m = random.randbytes(random.randint(0, 1024))
        a = pleth.keccak.sha3_384(bytearray(m))
        b = hashlib.sha3_384(m).digest()
        assert a == b


def test_sha3_512():
    for _ in range(4):
        m = random.randbytes(random.randint(0, 1024))
        a = pleth.keccak.sha3_512(bytearray(m))
        b = hashlib.sha3_512(m).digest()
        assert a == b
