import typing


def encode(data: int | bytearray | typing.List) -> bytearray:
    if isinstance(data, int):
        return encode(bytearray(data.to_bytes(32)).lstrip(bytearray([0x00])))
    if isinstance(data, bytearray):
        body = bytearray()
        if len(data) == 0x01 and data[0] <= 0x7f:
            body.extend(data)
            return body
        if len(data) <= 0x37:
            body.append(0x80 + len(data))
            body.extend(data)
            return body
        size = bytearray(len(data).to_bytes(32)).lstrip(bytearray([0x00]))
        body.append(0xb7 + len(size))
        body.extend(size)
        body.extend(data)
        return body
    if isinstance(data, list):
        head = bytearray()
        body = bytearray()
        for e in data:
            body.extend(encode(e))
        if len(body) <= 0x37:
            head.append(0xc0 + len(body))
            return head + body
        size = bytearray(len(body).to_bytes(32)).lstrip(bytearray([0x00]))
        head.append(0xf7 + len(size))
        head.extend(size)
        return head + body
    raise Exception('unreachable')


def decode(data: bytearray) -> bytearray | typing.List[bytearray]:
    if data[0] <= 0x7f:
        return bytearray([data[0]])
    if data[0] <= 0xb7:
        size = data[0] - 0x80
        return data[1:1+size]
    if data[0] <= 0xbf:
        nlen = data[0] - 0xb7
        size = int.from_bytes(data[1:1+nlen])
        body = data[1+nlen:1+nlen+size]
        return body
    if data[0] <= 0xf7:
        size = data[0] - 0xc0
        body = data[1:1+size]
        rets = []
        offs = 0
        while offs < len(body):
            item = decode(body[offs:])
            rets.append(item)
            offs += len(encode(item))
        return rets
    if data[0] <= 0xff:
        nlen = data[0] - 0xf7
        size = int.from_bytes(data[1:1+nlen])
        body = data[1+nlen:1+nlen+size]
        rets = []
        offs = 0
        while offs < len(body):
            item = decode(body[offs:])
            rets.append(item)
            offs += len(encode(item))
        return rets
    raise Exception('unreachable')
