import itertools
import pleth.secp256k1
import secrets
import typing


def sign(prikey: pleth.secp256k1.Fr, m: pleth.secp256k1.Fr) -> typing.Tuple[pleth.secp256k1.Fr, pleth.secp256k1.Fr, int]:
    # https://www.secg.org/sec1-v2.pdf
    # 4.1.3 Signing Operation
    for _ in itertools.repeat(0):
        k = pleth.secp256k1.Fr(max(1, secrets.randbelow(pleth.secp256k1.N)))
        R = pleth.secp256k1.G * k
        r = pleth.secp256k1.Fr(R.x.n)
        if r.n == 0:
            continue
        s = (m + prikey * r) / k
        if s.n == 0:
            continue
        v = 0
        if R.y.n & 1 == 1:
            v |= 1
        if R.x.n >= pleth.secp256k1.N:
            v |= 2
        return r, s, v
    raise Exception('unreachable')


def verify(pubkey: pleth.secp256k1.Pt, m: pleth.secp256k1.Fr, r: pleth.secp256k1.Fr, s: pleth.secp256k1.Fr) -> bool:
    # https://www.secg.org/sec1-v2.pdf
    # 4.1.4 Verifying Operation
    a = m / s
    b = r / s
    R = pleth.secp256k1.G * a + pubkey * b
    assert R != pleth.secp256k1.I
    return r == pleth.secp256k1.Fr(R.x.n)


def pubkey(m: pleth.secp256k1.Fr, r: pleth.secp256k1.Fr, s: pleth.secp256k1.Fr, v: int) -> pleth.secp256k1.Pt:
    # https://www.secg.org/sec1-v2.pdf
    # 4.1.6 Public Key Recovery Operation
    assert v in [0, 1, 2, 3]
    if v & 2 == 0:
        x = pleth.secp256k1.Fq(r.n)
    else:
        x = pleth.secp256k1.Fq(r.n + pleth.secp256k1.N)
    z = x * x * x + pleth.secp256k1.A * x + pleth.secp256k1.B
    y = z ** ((pleth.secp256k1.P + 1) // 4)
    if v & 1 != y.n & 1:
        y = -y
    R = pleth.secp256k1.Pt(x, y)
    return (R * s - pleth.secp256k1.G * m) / r
