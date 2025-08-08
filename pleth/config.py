import random
import requests
import typing


class ObjectDict(dict):
    def __getattr__(self, name: str) -> typing.Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name: str, value: typing.Any):
        self[name] = value


develop = ObjectDict({
    'chain_id': 1337,
    'gas_base_fee': 21000,
    'rpc': ObjectDict({
        'url': 'http://127.0.0.1:8545',
        'qps': 32,
    })
})

mainnet = ObjectDict({
    'chain_id': 1,
    'gas_base_fee': 21000,
    'rpc': ObjectDict({
        'url': 'https://eth.drpc.org',
        'qps': 2,
    })
})

testnet = ObjectDict({
    'chain_id': 11155111,
    'gas_base_fee': 21000,
    'rpc': ObjectDict({
        'url': 'https://rpc.sepolia.org',
        'qps': 2,
    })
})


def upgrade(url: str):
    develop.chain_id = int(requests.post(url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': 'eth_chainId',
        'params': []
    }).json()['result'], 0)
    develop.url = url


current = develop
