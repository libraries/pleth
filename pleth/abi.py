import pleth.core

# The Contract Application Binary Interface (ABI) is the standard way to interact with contracts in the Ethereum
# ecosystem, both from outside the blockchain and for contract-to-contract interaction. Data is encoded according to
# its type, as described in this specification. The encoding is not self describing and thus requires a schema in order
# to decode.
#
# See: https://docs.soliditylang.org/en/latest/abi-spec.html


def encode_uint256(data: int) -> bytearray:
    assert data >= 0
    assert data <= 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    return bytearray(data.to_bytes(32))


def decode_uint256(data: bytearray) -> int:
    assert len(data) == 32
    return int.from_bytes(data)


def encode_address(data: bytearray) -> bytearray:
    assert len(data) == 20
    return bytearray(12) + data


def decode_address(data: bytearray) -> bytearray:
    assert len(data) == 32
    return data[12:]


def function_selector(name: str, args_type: list[str]) -> bytearray:
    s = name + '(' + ','.join(args_type) + ')'
    return pleth.core.hash(bytearray(s.encode()))[:4]


def argument_encoding(data: list[bytearray]) -> bytearray:
    s = bytearray()
    for e in data:
        s.extend(e)
    return s
