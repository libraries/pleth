import itertools
import pleth.config
import pleth.rate
import random
import requests
import typing

# Doc: https://ethereum.org/en/developers/docs/apis/json-rpc/


def call(method: str, params: typing.List) -> typing.Any:
    if not hasattr(call, 'rate'):
        setattr(call, 'rate', pleth.rate.Limits(pleth.config.current.rpc.qps, 1))
    getattr(call, 'rate').wait(1)
    r = requests.post(pleth.config.current.rpc.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': method,
        'params': params,
    }).json()
    if 'error' in r:
        raise Exception(r['error'])
    return r['result']


def eth_accounts() -> typing.List[str]:
    return call('eth_accounts', [])


def eth_block_number() -> str:
    return call('eth_blockNumber', [])


def eth_call(body: typing.Dict, block_number: str) -> str:
    return call('eth_call', [body, block_number])


def eth_chain_id() -> str:
    return call('eth_chainId', [])


def eth_coinbase() -> str:
    return call('eth_coinbase', [])


def eth_estimate_gas(body: typing.Dict, block_number: str) -> str:
    return call('eth_estimateGas', [body, block_number])


def eth_gas_price() -> str:
    return call('eth_gasPrice', [])


def eth_get_balance(addr: str, block_number: str) -> str:
    return call('eth_getBalance', [addr, block_number])


def eth_get_block_by_hash(hash: str) -> typing.Dict:
    return call('eth_getBlockByHash', [hash, True])


def eth_get_block_by_number(block_number: str) -> typing.Dict:
    return call('eth_getBlockByNumber', [block_number, True])


def eth_get_block_transaction_count_by_hash(hash: str) -> str:
    return call('eth_getBlockTransactionCountByHash', [hash])


def eth_get_block_transaction_count_by_number(block_number: str) -> str:
    return call('eth_getBlockTransactionCountByNumber', [block_number])


def eth_get_code(addr: str, block_number: str) -> str:
    return call('eth_getCode', [addr, block_number])


def eth_get_filter_changes(id: str) -> typing.List[typing.Dict]:
    return call('eth_getFilterChanges', [id])


def eth_get_filter_logs(id: str) -> typing.List[typing.Dict]:
    return call('eth_getFilterLogs', [id])


def eth_get_logs(option: typing.Dict) -> typing.List[typing.Dict]:
    return call('eth_getLogs', [option])


def eth_get_storage_at(addr: str, position: str, block_number: str) -> str:
    return call('eth_getStorageAt', [addr, position, block_number])


def eth_get_transaction_by_block_hash_and_index(hash: str, index: str):
    return call('eth_getTransactionByBlockHashAndIndex', [hash, index])


def eth_get_transaction_by_block_number_and_index(block_number: str, index: str):
    return call('eth_getTransactionByBlockNumberAndIndex', [block_number, index])


def eth_get_transaction_by_hash(hash: str) -> typing.Dict:
    return call('eth_getTransactionByHash', [hash])


def eth_get_transaction_count(addr: str, block_number: str) -> str:
    return call('eth_getTransactionCount', [addr, block_number])


def eth_get_transaction_receipt(hash: str) -> typing.Dict:
    return call('eth_getTransactionReceipt', [hash])


def eth_get_uncle_by_block_hash_and_index(hash: str, index: str):
    return call('eth_getUncleByBlockHashAndIndex', [hash, index])


def eth_get_uncle_by_block_number_and_index(block_number: str, index: str):
    return call('eth_getUncleByBlockNumberAndIndex', [block_number, index])


def eth_get_uncle_count_by_block_hash(hash: str) -> str:
    return call('eth_getUncleCountByBlockHash', [hash])


def eth_get_uncle_count_by_block_number(block_number: str) -> str:
    return call('eth_getUncleCountByBlockNumber', [block_number])


def eth_hashrate() -> str:
    return call('eth_hashrate', [])


def eth_max_priority_fee_per_gas() -> str:
    return call('eth_maxPriorityFeePerGas', [])


def eth_mining() -> bool:
    return call('eth_mining', [])


def eth_new_block_filter() -> str:
    return call('eth_newBlockFilter', [])


def eth_new_filter(option: typing.Dict) -> str:
    return call('eth_newFilter', [option])


def eth_new_pending_transaction_filter() -> str:
    return call('eth_newPendingTransactionFilter', [])


def eth_protocol_version() -> str:
    return call('eth_protocolVersion', [])


def eth_send_raw_transaction(tx: str) -> str:
    return call('eth_sendRawTransaction', [tx])


def eth_send_transaction(tx: typing.Dict) -> str:
    return call('eth_sendTransaction', [tx])


def eth_sign(addr: str, message: str) -> str:
    return call('eth_sign', [addr, message])


def eth_sign_transaction(tx: typing.Dict) -> str:
    return call('eth_signTransaction', [tx])


def eth_syncing() -> typing.Dict:
    return call('eth_syncing', [])


def eth_uninstall_filter(id: str):
    return call('eth_uninstallFilter', [id])


def net_version() -> str:
    return call('net_version', [])


def net_listening() -> bool:
    return call('net_listening', [])


def net_peer_count() -> str:
    return call('net_peerCount', [])


def wait(hash: str) -> None:
    for _ in itertools.repeat(0):
        r = eth_get_transaction_by_hash(hash)
        if not r:
            continue
        if not r['blockNumber']:
            continue
        r = eth_get_transaction_receipt(hash)
        if not r:
            continue
        if int(r['status'], 0) != 1:
            raise Exception(r['status'])
        break


def web3_client_version() -> str:
    return call('web3_clientVersion', [])


def web3_sha3(data: str) -> str:
    return call('web3_sha3', [data])
