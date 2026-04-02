# Implementation by Mohanson.
#
# See: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

ROTATION_SHIFTS: list[list[int]] = [
    [0x00, 0x24, 0x03, 0x29, 0x12],
    [0x01, 0x2c, 0x0a, 0x2d, 0x02],
    [0x3e, 0x06, 0x2b, 0x0f, 0x3d],
    [0x1c, 0x37, 0x19, 0x15, 0x38],
    [0x1b, 0x14, 0x27, 0x08, 0x0e],
]

ROUND_CONSTANTS: list[int] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]


def rol(n: int, s: int) -> int:
    s %= 64
    return ((n << s) & 0xffffffffffffffff) | (n >> (64 - s))


def b2s(b: bytearray) -> list[list[int]]:
    a: list[list[int]] = [[0] * 5 for _ in range(5)]
    for i in range(25):
        x, y = i % 5, i // 5
        a[x][y] = int.from_bytes(b[i * 8: i * 8 + 8], 'little')
    return a


def s2b(a: list[list[int]]) -> bytearray:
    b = bytearray(200)
    for i in range(25):
        x, y = i % 5, i // 5
        b[i * 8: i * 8 + 8] = a[x][y].to_bytes(8, 'little')
    return b


def keccak_round(a: list[list[int]], n: int) -> list[list[int]]:
    # Step mappings: θ
    c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
    d = [c[(x+4) % 5] ^ rol(c[(x+1) % 5], 1) for x in range(5)]
    a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
    # Step mappings: ρ
    a = [[rol(a[x][y], ROTATION_SHIFTS[x][y]) for y in range(5)] for x in range(5)]
    # Step mappings: π
    b = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            b[y][(2 * x + 3 * y) % 5] = a[x][y]
    a = b
    # Step mappings: x
    for y in range(5):
        t = [a[x][y] for x in range(5)]
        for x in range(5):
            a[x][y] = t[x] ^ ((~t[(x+1) % 5]) & t[(x+2) % 5])
    # Step mappings: ι
    a[0][0] ^= n
    return a


def keccak_f(a: list[list[int]]) -> list[list[int]]:
    for i in range(24):
        a = keccak_round(a, ROUND_CONSTANTS[i])
    return a


def keccak(r: int, c: int, l: int, d: int, m: bytearray) -> bytearray:
    assert r + c == 200
    m = m.copy()
    m.append(d)
    m.extend(bytearray(-len(m) % r))
    m[-1] ^= 0x80
    state = bytearray(200)
    for block_start in range(0, len(m), r):
        block = m[block_start:block_start + r]
        for i in range(r):
            state[i] ^= block[i]
        state = s2b(keccak_f(b2s(state)))
    event = bytearray()
    while l > 0:
        chunk = min(l, r)
        event.extend(state[0:chunk])
        l -= chunk
        if l > 0:
            state = s2b(keccak_f(b2s(state)))
    return event


def shake128(m: bytearray, l: int) -> bytearray:
    return keccak(168, 32, l, 0x1f, m)


def shake256(m: bytearray, l: int) -> bytearray:
    return keccak(136, 64, l, 0x1f, m)


def sha3_224(m: bytearray) -> bytearray:
    return keccak(144, 56, 28, 0x06, m)


def sha3_256(m: bytearray) -> bytearray:
    return keccak(136, 64, 32, 0x06, m)


def sha3_384(m: bytearray) -> bytearray:
    return keccak(104, 96, 48, 0x06, m)


def sha3_512(m: bytearray) -> bytearray:
    return keccak(72, 128, 64, 0x06, m)


def hash(m: bytearray) -> bytearray:
    # Ethereum uses keccak-256, while the official sha3-256 is the NIST-standardized version of the same algorithm.
    # They produce different hash outputs for the same input because of a small change in the padding rule.  Keccak-256
    # uses the original padding constant 0x01. NIST changed this to 0x06 for the final sha3-256 standard (fips 202) to
    # support future "tree hashing" and domain separation.
    return keccak(136, 64, 32, 0x01, m)
