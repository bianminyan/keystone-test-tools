import hashlib
import sys
from aptos_sdk.account import Account as APT_Account
from bip_utils import (
    Bip44,
    Bip44Coins,
    Bip44Changes,
    Bip49,
    Bip49Coins,
    Bip84,
    Bip84Coins,
    Bip86,
    Bip86Coins,
    Bip32Slip10Ed25519,
    Bip32Slip10Secp256k1,
    XrpAddr,
)

from cashaddress import convert
from solders.keypair import Keypair as SoldersKeypair, Keypair
from stellar_sdk import Keypair as StellarKeypair
from pycardano.crypto.bip32 import HDWallet as Adahdwallet
from pycardano.address import Address as AdaAddress
from pycardano.key import PaymentVerificationKey
from pycardano.network import Network
from base58 import b58decode_check, b58encode_check
import binascii
from typing import Optional, Union
from cosmospy import generate_wallet, pubkey_to_address, privkey_to_pubkey
try:
    from pyinjective import PrivateKey as INJPrivateKey
except ImportError:
    INJPrivateKey = None
import bech32
import base58
import os
import subprocess
from tonsdk.contract.wallet import WalletVersionEnum, Wallets
recover_slip39 = None
try:
    # 首先尝试导入 hdwallet_slip39（slip39 包自带的 hdwallet）
    try:
        import hdwallet_slip39.cryptocurrencies as crypto_module
    except ImportError:
        # 如果没有 hdwallet_slip39，尝试标准 hdwallet
        import hdwallet.cryptocurrencies as crypto_module
    # 如果 hdwallet 有 ICryptocurrency 而不是 Cryptocurrency，创建别名
    if hasattr(crypto_module, 'ICryptocurrency') and not hasattr(crypto_module, 'Cryptocurrency'):
        crypto_module.Cryptocurrency = crypto_module.ICryptocurrency
    
    # 修复 CoinType 和 SegwitAddress 属性问题
    # slip39 库需要这些类，它们应该接受字典参数
    if not hasattr(crypto_module, 'CoinType'):
        # 创建一个兼容的 CoinType 类
        # CoinType 在旧版本的 hdwallet 中是一个可以接受字典的类
        class CoinType:
            """兼容的 CoinType 类，用于支持 slip39 库"""
            def __init__(self, coin_data):
                # coin_data 是一个字典，包含币种信息
                # 我们将字典的内容存储为属性
                if isinstance(coin_data, dict):
                    for key, value in coin_data.items():
                        setattr(self, key, value)
                else:
                    # 如果不是字典，直接存储
                    self.data = coin_data
        crypto_module.CoinType = CoinType
    
    if not hasattr(crypto_module, 'SegwitAddress'):
        # 创建一个兼容的 SegwitAddress 类
        # SegwitAddress 也接受字典参数
        class SegwitAddress:
            """兼容的 SegwitAddress 类，用于支持 slip39 库"""
            def __init__(self, address_data):
                # address_data 是一个字典，包含地址信息（如 HRP, VERSION）
                if isinstance(address_data, dict):
                    for key, value in address_data.items():
                        setattr(self, key, value)
                else:
                    self.data = address_data
        crypto_module.SegwitAddress = SegwitAddress
    
    # 现在尝试导入 slip39
    # 注意：slip39 的 __init__.py 会导入 api 模块，所以我们需要在导入前修复兼容性
    # slip39 1.0.0 版本的 recover 函数直接在 slip39 模块中
    import slip39
    recover_slip39 = slip39.recover
except ImportError as e:
    # hdwallet 或 slip39 未安装
    error_msg = str(e)
    if 'hdwallet' in error_msg:
        print("Error: hdwallet is not installed.", file=sys.stderr)
        print("  Please install it with: pip install hdwallet", file=sys.stderr)
    elif 'slip39' in error_msg:
        print("Error: slip39 is not installed.", file=sys.stderr)
        print("  Please install it with: pip install slip39", file=sys.stderr)
    else:
        print(f"Warning: Import error: {error_msg}", file=sys.stderr)
    recover_slip39 = None
except (AttributeError, ModuleNotFoundError, TypeError) as e:
    # 如果导入失败，提供友好的错误信息
    error_msg = str(e)
    missing_attr = None
    if 'CoinType' in error_msg:
        missing_attr = 'CoinType'
    elif 'Cryptocurrency' in error_msg:
        missing_attr = 'Cryptocurrency'
    elif 'SegwitAddress' in error_msg:
        missing_attr = 'SegwitAddress'
    elif 'ExtendedPrivateKey' in error_msg:
        missing_attr = 'ExtendedPrivateKey'
    
    if missing_attr:
        print(f"Error: hdwallet version incompatibility detected - missing '{missing_attr}'.", file=sys.stderr)
        print("  The slip39 library requires an older, compatible version of hdwallet.", file=sys.stderr)
        print("  Current hdwallet version may be too new and incompatible with slip39.", file=sys.stderr)
        print("", file=sys.stderr)
        print("  To fix this, please install compatible versions:", file=sys.stderr)
        print("    pip uninstall hdwallet slip39", file=sys.stderr)
        print("    pip install 'hdwallet==1.1.1' 'slip39==1.0.0'", file=sys.stderr)
        print("", file=sys.stderr)
        print("  Or if you need to keep the current hdwallet version,", file=sys.stderr)
        print("  you may need to use an alternative SLIP-39 implementation.", file=sys.stderr)
    else:
        print(f"Warning: slip39 library import failed: {error_msg}", file=sys.stderr)
        print("Please ensure slip39 and hdwallet are installed and compatible.", file=sys.stderr)
        print("  Try: pip install 'hdwallet==1.1.1' 'slip39==1.0.0'", file=sys.stderr)
    recover_slip39 = None
except Exception as e:
    # 其他未知错误
    print(f"Warning: Unexpected error importing slip39: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc()
    recover_slip39 = None

# Python 3.13 下 old slip39/hdwallet 组合常见不兼容，使用 shamir_mnemonic 兜底
if recover_slip39 is None:
    try:
        from shamir_mnemonic import combine_mnemonics

        def recover_slip39(mnemonics, passphrase=b""):
            return combine_mnemonics(mnemonics, passphrase=passphrase)

        print("Info: using shamir_mnemonic fallback for SLIP-39 recovery.", file=sys.stderr)
    except Exception:
        pass


def hash160(data: bytes) -> bytes:
    sha_hash = hashlib.sha256(data).digest()
    ripemd = hashlib.new("ripemd160")
    ripemd.update(sha_hash)
    return ripemd.digest()
def slip39_menmonic_to_seed(mnemonic: str, passphrase: Optional[Union[bytes, str]] = None,
                            using_bip39: bool = False) -> str:
    if recover_slip39 is None:
        raise RuntimeError("slip39 library is not available. Please install compatible versions of slip39 and hdwallet.")
    
    mnemonics_lines = [
        s.strip()
        for s in mnemonic.split('\n')
        if s.strip()
    ]
    if len(mnemonics_lines) < 1:
        raise ValueError("At least one BIP-39 or SLIP-39 Mnemonics required")
    # SLIP-39 supports single-share 1-of-1 groups, which are commonly 33 words.
    # recover_slip39 accepts List[str] where each entry is one complete share.
    if passphrase is None:
        passphrase_bytes = b''
    elif isinstance(passphrase, str):
        passphrase_bytes = passphrase.encode('utf-8')
    else:
        passphrase_bytes = passphrase

    seed_bytes = recover_slip39(mnemonics_lines, passphrase=passphrase_bytes)
    seed = binascii.hexlify(seed_bytes).decode()
    return seed


def slip39_menmonic_to_byte_seed(mnemonic: str, passphrase: Optional[Union[bytes, str]] = None,
                                 using_bip39: bool = False) -> bytes:
    if recover_slip39 is None:
        raise RuntimeError("slip39 library is not available. Please install compatible versions of slip39 and hdwallet.")
    
    mnemonics_lines = [
        s.strip()
        for s in mnemonic.split('\n')
        if s.strip()
    ]
    if len(mnemonics_lines) < 1:
        raise ValueError("At least one BIP-39 or SLIP-39 Mnemonics required")
    if passphrase is None:
        passphrase_bytes = b''
    elif isinstance(passphrase, str):
        passphrase_bytes = passphrase.encode('utf-8')
    else:
        passphrase_bytes = passphrase

    byte_seed = recover_slip39(mnemonics_lines, passphrase=passphrase_bytes)
    return byte_seed


class count_btc_address:
    """
    BTC地址计算
    """
    prefixes = {
        'xpub': '0488b21e',
        'ypub': '049d7cb2',
        'Ypub': '0295b43f',
        'zpub': '04b24746',
        'Zpub': '02aa7ed3',
        'tpub': '043587cf',
        'upub': '044a5262',
        'Upub': '024289ef',
        'vpub': '045f1cf6',
        'Vpub': '02575483',
    }

    def __init__(self, account=0, change=False, size=5, slip39_seed="", testnet=False):
        # 如果 slip39_seed 是字符串（hex），转换为字节
        if isinstance(slip39_seed, str):
            slip39_seed = bytes.fromhex(slip39_seed)

        self.account = account
        self.change = change
        self.size = size
        self.testnet = testnet
        self.seed = slip39_seed

        bip44_coin = Bip44Coins.BITCOIN_TESTNET if self.testnet else Bip44Coins.BITCOIN
        bip49_coin = Bip49Coins.BITCOIN_TESTNET if self.testnet else Bip49Coins.BITCOIN
        bip84_coin = Bip84Coins.BITCOIN_TESTNET if self.testnet else Bip84Coins.BITCOIN
        bip86_coin = Bip86Coins.BITCOIN_TESTNET if self.testnet else Bip86Coins.BITCOIN

        self._bip44_account = Bip44.FromSeed(self.seed, bip44_coin).Purpose().Coin().Account(self.account)
        self._bip49_account = Bip49.FromSeed(self.seed, bip49_coin).Purpose().Coin().Account(self.account)
        self._bip84_account = Bip84.FromSeed(self.seed, bip84_coin).Purpose().Coin().Account(self.account)
        self._bip86_account = Bip86.FromSeed(self.seed, bip86_coin).Purpose().Coin().Account(self.account)
        
        self.seed_slip44_address = self._derive_addresses(self._bip44_account)
        self.seed_slip49_address = self._derive_addresses(self._bip49_account)
        self.seed_slip84_address = self._derive_addresses(self._bip84_account)
        self.seed_slip86_address = self._derive_addresses(self._bip86_account)

        self.seed_slip44_xpublic_key = self._bip44_account.PublicKey().ToExtended()
        self.seed_slip49_xpublic_key = self._bip49_account.PublicKey().ToExtended()
        self.seed_slip84_xpublic_key = self._bip84_account.PublicKey().ToExtended()
        self.seed_slip86_xpublic_key = self._bip86_account.PublicKey().ToExtended()

        canonical_prefix = 'tpub' if self.testnet else 'xpub'
        canonical_keep = ('tpub',) if self.testnet else ('xpub',)
        self.seed_slip44_canonical_xpub = self._change_version_bytes(self.seed_slip44_xpublic_key, canonical_prefix, canonical_keep)
        self.seed_slip49_canonical_xpub = self._change_version_bytes(self.seed_slip49_xpublic_key, canonical_prefix, canonical_keep)
        self.seed_slip84_canonical_xpub = self._change_version_bytes(self.seed_slip84_xpublic_key, canonical_prefix, canonical_keep)
        self.seed_slip86_canonical_xpub = self._change_version_bytes(self.seed_slip86_xpublic_key, canonical_prefix, canonical_keep)

        if self.testnet:
            self.seed_slip49_public_key = self._change_version_bytes(self.seed_slip49_xpublic_key, 'upub', ('upub', 'Upub'))
            self.seed_slip84_public_key = self._change_version_bytes(self.seed_slip84_xpublic_key, 'vpub', ('vpub', 'Vpub'))
        else:
            self.seed_slip49_public_key = self._change_version_bytes(self.seed_slip49_xpublic_key, 'ypub', ('ypub', 'Ypub'))
            self.seed_slip84_public_key = self._change_version_bytes(self.seed_slip84_xpublic_key, 'zpub', ('zpub', 'Zpub'))

        self.multisig_xpubs = self._derive_multisig_xpubs()

    def _change_enum(self):
        return Bip44Changes.CHAIN_INT if self.change else Bip44Changes.CHAIN_EXT

    def _derive_addresses(self, account_ctx):
        change_ctx = account_ctx.Change(self._change_enum())
        return [change_ctx.AddressIndex(i).PublicKey().ToAddress() for i in range(self.size)]

    def _change_version_bytes(self, extended_key, target_key, keep_prefixes):
        if extended_key.startswith(keep_prefixes):
            return extended_key
        data = b58decode_check(extended_key.strip())
        converted = bytes.fromhex(count_btc_address.prefixes[target_key]) + data[4:]
        return b58encode_check(converted).decode()

    def _derive_multisig_xpubs(self):
        coin_type = 1 if self.testnet else 0
        bip32_ctx = Bip32Slip10Secp256k1.FromSeed(self.seed)

        canonical_prefix = 'tpub' if self.testnet else 'xpub'
        canonical_keep = ('tpub',) if self.testnet else ('xpub',)

        # Legacy multisig 使用 BIP45 路径 m/45'
        legacy_node = bip32_ctx.DerivePath("m/45'")
        legacy_extended = legacy_node.PublicKey().ToExtended()

        result = [{
            "script": "Legacy (P2SH)",
            "path": "m/45'",
            "xpub": self._change_version_bytes(legacy_extended, canonical_prefix, canonical_keep),
        }]

        # Nested/Native multisig 使用 BIP48 路径
        script_entries = [
            ("Nested Segwit (P2SH-P2WSH)", 1),
            ("Native Segwit (P2WSH)", 2),
        ]

        for script_name, script_type in script_entries:
            path = f"m/48'/{coin_type}'/{self.account}'/{script_type}'"
            node = bip32_ctx.DerivePath(path)
            extended_key = node.PublicKey().ToExtended()
            converted = self._change_version_bytes(extended_key, canonical_prefix, canonical_keep)
            result.append({
                "script": script_name,
                "path": path,
                "xpub": converted,
            })
        return result


class count_eth_address:
    """
    ETH地址计算
    """

    def __init__(self, account=0, change=False, size=10, slip39_seed=""):
        # 如果 slip39_seed 是字符串（hex），转换为字节
        if isinstance(slip39_seed, str):
            slip39_seed = bytes.fromhex(slip39_seed)

        self.account = account
        self.change = change
        self.size = size
        self.seed = slip39_seed
        self._coin_ctx = Bip44.FromSeed(self.seed, Bip44Coins.ETHEREUM).Purpose().Coin()
        
        self.seed_slip44_address = self._derive_standard_addresses()
        self.seed_ledger_live_address = self._derive_ledger_live_addresses()
        self.seed_ledger_legacy_address = self._derive_ledger_legacy_addresses()

    def _change_enum(self):
        return Bip44Changes.CHAIN_INT if self.change else Bip44Changes.CHAIN_EXT

    def _derive_standard_addresses(self):
        account_ctx = self._coin_ctx.Account(self.account)
        change_ctx = account_ctx.Change(self._change_enum())
        return [change_ctx.AddressIndex(i).PublicKey().ToAddress() for i in range(self.size)]

    def _derive_ledger_live_addresses(self):
        addr_list = []
        for i in range(self.size):
            account_ctx = self._coin_ctx.Account(i)
            change_ctx = account_ctx.Change(self._change_enum())
            addr_list.append(change_ctx.AddressIndex(0).PublicKey().ToAddress())
        return addr_list

    def _derive_ledger_legacy_addresses(self):
        # Ledger Legacy 使用 4 层路径: m/44'/60'/0'/{i}
        # 不包含 change 层级，直接在 account 后派生地址索引
        from bip_utils import Bip32Slip10Secp256k1
        from eth_hash.auto import keccak
        
        bip32_ctx = Bip32Slip10Secp256k1.FromSeed(self.seed)
        # m/44'/60'/0'
        bip32_ctx = bip32_ctx.ChildKey(0x8000002C)  # 44'
        bip32_ctx = bip32_ctx.ChildKey(0x8000003C)  # 60'
        bip32_ctx = bip32_ctx.ChildKey(0x80000000)  # 0'
        
        addr_list = []
        for i in range(self.size):
            # 派生第 i 个地址 (非强化)
            child_ctx = bip32_ctx.ChildKey(i)
            # 获取未压缩公钥并去掉 0x04 前缀
            pub_key_bytes = child_ctx.PublicKey().RawUncompressed().ToBytes()[1:]
            # ETH 地址 = keccak256(pubkey)[-20:] 并加上 0x 前缀和 checksum
            addr_bytes = keccak(pub_key_bytes)[-20:]
            # 转换为带 checksum 的地址
            addr_hex = addr_bytes.hex()
            # 计算 checksum
            hash_hex = keccak(addr_hex.encode()).hex()
            checksum_addr = '0x'
            for j, c in enumerate(addr_hex):
                if c in '0123456789':
                    checksum_addr += c
                else:
                    checksum_addr += c.upper() if int(hash_hex[j], 16) >= 8 else c.lower()
            addr_list.append(checksum_addr)
        
        return addr_list



class count_solana_address:
    """
       SOL地址计算
    """

    def __init__(self,size=50, slip39_seed=""):

        self.size = size
        self.sub_account_path_address = self._from_mnemonic_sub_account_path_address(slip39_seed)
        self.account_based_path_address = self._from_mnemonic_account_based_path_address(slip39_seed)
        self.single_account_path_address = self._from_mnemonic_single_account_path_address(slip39_seed)

    def _from_mnemonic_sub_account_path_address(self,slip39_seed):
        if Keypair is None:
            raise RuntimeError("solders not installed. Please install it with: pip install solders")
        addr_list = [i for i in range(self.size)]
        for i in range(self.size):
            bip44_sol = Bip44.FromSeed(slip39_seed, Bip44Coins.SOLANA)
            account = bip44_sol.Purpose().Coin().Account(i).Change(Bip44Changes.CHAIN_EXT)
            private_key_bytes = account.PrivateKey().Raw().ToBytes()
            # 从私钥生成 Keypair 并获取公钥（Solana 地址）
            keypair = Keypair.from_seed(private_key_bytes)
            sol_address = keypair.pubkey()
            addr_list[i]=sol_address
        return addr_list

    def _from_mnemonic_account_based_path_address(self,slip39_seed):
        if Keypair is None:
            raise RuntimeError("solders not installed. Please install it with: pip install solders")
        addr_list = [i for i in range(self.size)]
        for i in range(self.size):
            bip44_sol = Bip44.FromSeed(slip39_seed, Bip44Coins.SOLANA)
            account = bip44_sol.Purpose().Coin().Account(i)
            private_key_bytes = account.PrivateKey().Raw().ToBytes()
            # 从私钥生成 Keypair 并获取公钥（Solana 地址）
            keypair = Keypair.from_seed(private_key_bytes)
            sol_address = keypair.pubkey()
            addr_list[i] = sol_address
        return addr_list

    def _from_mnemonic_single_account_path_address(self,slip39_seed):
        if Keypair is None:
            raise RuntimeError("solders not installed. Please install it with: pip install solders")
        bip44_sol = Bip44.FromSeed(slip39_seed, Bip44Coins.SOLANA)
        account = bip44_sol.Purpose().Coin()
        private_key_bytes = account.PrivateKey().Raw().ToBytes()
        # 从私钥生成 Keypair 并获取公钥（Solana 地址）
        keypair = Keypair.from_seed(private_key_bytes)
        address = keypair.pubkey()
        return address


class count_avax_address:
    """
    AVAX地址计算
        """

    def __init__(self, account=0, change=False, size=10, slip39_seed=""):
        # 如果 slip39_seed 是字符串（hex），转换为字节
        if isinstance(slip39_seed, str):
            slip39_seed = bytes.fromhex(slip39_seed)

        self.account = account
        self.change = change
        self.size = size
        self.seed = slip39_seed
        self.seed_slip44_address = self._from_seed_bip44_address()
        self.avax_address = self._from_mnemonic_avax_address()

    def _from_seed_bip44_address(self):
        # AVAX P/X 链使用 coin type 9000，对应路径 m/44'/9000'/X'/0/0
        # 这里 X 作为 account 维度递增
        addr_list = []
        for acc in range(self.account, self.account + self.size):
            account_ctx = Bip44.FromSeed(self.seed, Bip44Coins.AVAX_X_CHAIN).Purpose().Coin().Account(acc)
            change_ctx = account_ctx.Change(Bip44Changes.CHAIN_INT if self.change else Bip44Changes.CHAIN_EXT)
            addr_list.append(change_ctx.AddressIndex(0).PublicKey().ToAddress())
        return addr_list

    def _from_mnemonic_avax_address(self):
        addr_list = []
        # 与 bip39 版本保持一致：对每个 X(=account) 取 index=0
        for acc in range(self.account, self.account + self.size):
            account_ctx = Bip44.FromSeed(self.seed, Bip44Coins.AVAX_X_CHAIN).Purpose().Coin().Account(acc)
            change_ctx = account_ctx.Change(Bip44Changes.CHAIN_EXT)
            bip44_address_key = change_ctx.AddressIndex(0)
            public_key = bip44_address_key.PublicKey().RawCompressed().ToBytes()
            address_hash = hash160(public_key)
            addr_list.append(bech32.bech32_encode("avax", bech32.convertbits(address_hash, 8, 5)))
        return addr_list


class count_xrp_address:

    def __init__(self, size=10, slip39_seed=""):
        self.size = size
        self.xrp_slip39_address = self._from_seed_hdwallet_address(slip39_seed)

    def _from_seed_hdwallet_address(self, slip39_seed):
        bip44_ctx = Bip44.FromSeed(slip39_seed, Bip44Coins.RIPPLE)
        addr_list = [i for i in range(self.size)]
        for i in range(self.size):
            account = bip44_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(i)
            private_key = account.PrivateKey().Raw().ToBytes()
            # 获取公钥并生成 XRP 地址
            public_key = account.PublicKey().RawCompressed().ToBytes()
            xrp_address = XrpAddr.EncodeKey(public_key)
            addr_list[i] = xrp_address
        return addr_list

class count_trx_address:
    """
    TRX地址计算
    """

    def __init__(self, account=0, change=False, size=10, slip39_seed=""):
        # 如果 slip39_seed 是字符串（hex），转换为字节
        if isinstance(slip39_seed, str):
            slip39_seed = bytes.fromhex(slip39_seed)
        
        self.account = account
        self.change = change
        self.size = size
        self.seed = slip39_seed
        self.trx_slip39_address = self._from_seed_bip44_address()

    def _from_seed_bip44_address(self):
        account_ctx = Bip44.FromSeed(self.seed, Bip44Coins.TRON).Purpose().Coin().Account(self.account)
        change_ctx = account_ctx.Change(Bip44Changes.CHAIN_INT if self.change else Bip44Changes.CHAIN_EXT)
        return [change_ctx.AddressIndex(i).PublicKey().ToAddress() for i in range(self.size)]

class count_ltc_address:
    """
    LTC地址计算，支持 BIP44 (Legacy P2PKH)、BIP49 (P2SH-SegWit)、BIP84 (Native SegWit)
    """

    def __init__(self, account=0, change=False, size=10, slip39_seed=""):
        # 如果 slip39_seed 是字符串（hex），转换为字节
        if isinstance(slip39_seed, str):
            slip39_seed = bytes.fromhex(slip39_seed)
        
        self.account = account
        self.change = change
        self.size = size
        self.seed = slip39_seed

        # 初始化各种 BIP 路径的账户上下文
        self._bip44_account = Bip44.FromSeed(self.seed, Bip44Coins.LITECOIN).Purpose().Coin().Account(self.account)
        self._bip49_account = Bip49.FromSeed(self.seed, Bip49Coins.LITECOIN).Purpose().Coin().Account(self.account)
        self._bip84_account = Bip84.FromSeed(self.seed, Bip84Coins.LITECOIN).Purpose().Coin().Account(self.account)

        # 派生地址
        self.ltc_slip44_address = self._derive_addresses(self._bip44_account)
        self.ltc_slip39_address = self._derive_addresses(self._bip49_account)  # 保持向后兼容
        self.ltc_slip49_address = self._derive_addresses(self._bip49_account)
        self.ltc_slip84_address = self._derive_addresses(self._bip84_account)

        # 派生扩展公钥
        self.bip44_xpublic_key = self._bip44_account.PublicKey().ToExtended()
        self.bip49_xpublic_key = self._bip49_account.PublicKey().ToExtended()
        self.bip84_xpublic_key = self._bip84_account.PublicKey().ToExtended()

    def _derive_addresses(self, account_ctx):
        """派生地址列表"""
        change_ctx = account_ctx.Change(self._change_enum())
        return [change_ctx.AddressIndex(i).PublicKey().ToAddress() for i in range(self.size)]

    def _change_enum(self):
        """返回 change 枚举值"""
        return Bip44Changes.CHAIN_INT if self.change else Bip44Changes.CHAIN_EXT

    def count_especial_address(self, address_type, index):
        """计算指定类型的单个地址"""
        if address_type == "BIP44":
            return self._derive_single_address(self._bip44_account, index)
        if address_type == "BIP49":
            return self._derive_single_address(self._bip49_account, index)
        if address_type == "BIP84":
            return self._derive_single_address(self._bip84_account, index)
        raise ValueError(f"Unsupported address type: {address_type}")

    def _derive_single_address(self, account_ctx, index):
        """派生单个地址"""
        change_ctx = account_ctx.Change(self._change_enum())
        return change_ctx.AddressIndex(index).PublicKey().ToAddress()


class count_bch_address:

    def __init__(self, account=0, change=False, size=10, slip39_seed=""):
        # 如果 slip39_seed 是字符串（hex），转换为字节
        if isinstance(slip39_seed, str):
            slip39_seed = bytes.fromhex(slip39_seed)
        
        self.account = account
        self.change = change
        self.size = size
        self.seed = slip39_seed
        self.bch_slip39_address = self._from_seed_bip44_address()

    def _from_seed_bip44_address(self):
        account_ctx = Bip44.FromSeed(self.seed, Bip44Coins.BITCOIN_CASH).Purpose().Coin().Account(self.account)
        change_ctx = account_ctx.Change(Bip44Changes.CHAIN_INT if self.change else Bip44Changes.CHAIN_EXT)
        addr_list = []
        for i in range(self.size):
            bitpay_addr = change_ctx.AddressIndex(i).PublicKey().ToAddress()
            # Bip44Coins.BITCOIN_CASH returns CashAddr format (with ':')
            # If it's already CashAddr, use it directly; otherwise convert from Legacy
            if ':' in bitpay_addr:
                # Already in CashAddr format
                cash_addr = bitpay_addr
            else:
                # Legacy format, convert to CashAddr if cashaddress is available
                if convert is not None:
                    try:
                        legacy_addr = b58encode_check(b"\x00" + b58decode_check(bitpay_addr)[1:]).decode("utf-8")
                        cash_addr = convert.to_cash_address(legacy_addr)
                    except (ValueError, IndexError):
                        # If conversion fails, use the address as-is
                        cash_addr = bitpay_addr
                else:
                    cash_addr = bitpay_addr
            addr_list.append(cash_addr)
        return addr_list


class count_dash_address:
    """
    DASH地址计算
    """

    def __init__(self, account=0, change=False, size=10, slip39_seed=""):
        # 如果 slip39_seed 是字符串（hex），转换为字节
        if isinstance(slip39_seed, str):
            slip39_seed = bytes.fromhex(slip39_seed)
        
        self.account = account
        self.change = change
        self.size = size
        self.seed = slip39_seed
        self.dash_slip39_address = self._from_seed_bip44_address()

    def _from_seed_bip44_address(self):
        account_ctx = Bip44.FromSeed(self.seed, Bip44Coins.DASH).Purpose().Coin().Account(self.account)
        change_ctx = account_ctx.Change(Bip44Changes.CHAIN_INT if self.change else Bip44Changes.CHAIN_EXT)
        return [change_ctx.AddressIndex(i).PublicKey().ToAddress() for i in range(self.size)]


class count_doge_address:
    """
    DOGE地址计算
    """

    def __init__(self, account=0, change=False, size=10, slip39_seed=""):
        # 如果 slip39_seed 是字符串（hex），转换为字节
        if isinstance(slip39_seed, str):
            slip39_seed = bytes.fromhex(slip39_seed)
        
        self.account = account
        self.change = change
        self.size = size
        self.seed = slip39_seed
        self.doge_slip39_address = self._from_seed_bip44_address()

    def _from_seed_bip44_address(self):
        account_ctx = Bip44.FromSeed(self.seed, Bip44Coins.DOGECOIN).Purpose().Coin().Account(self.account)
        change_ctx = account_ctx.Change(Bip44Changes.CHAIN_INT if self.change else Bip44Changes.CHAIN_EXT)
        return [change_ctx.AddressIndex(i).PublicKey().ToAddress() for i in range(self.size)]


class count_xrp_address:

    def __init__(self, size=10, slip39_seed=""):
        self.size = size
        self.xrp_slip39_address = self._from_seed_hdwallet_address(slip39_seed)

    def _from_seed_hdwallet_address(self, slip39_seed):
        bip44_ctx = Bip44.FromSeed(slip39_seed, Bip44Coins.RIPPLE)
        addr_list = [i for i in range(self.size)]
        for i in range(self.size):
            account = bip44_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(i)
            private_key = account.PrivateKey().Raw().ToBytes()
            # 获取公钥并生成 XRP 地址
            public_key = account.PublicKey().RawCompressed().ToBytes()
            xrp_address = XrpAddr.EncodeKey(public_key)
            addr_list[i] = xrp_address
        return addr_list


class count_apt_address:

        def __init__(self, size=10, slip39_seed=""):
            if APT_Account is None:
                raise ImportError("aptos_sdk is not installed. Please install it with: pip install aptos-sdk")
            self.size = size
            self.bip44_address = self._from_mnemonic_bip44hdwallet_address(slip39_seed)

        def _from_mnemonic_bip44hdwallet_address(self, slip39_seed):
            """
            @param symbol: 币种
            @param account: 用户自定义账户索引
            @param change: False:0, True:1
            @param address: 地址索引
            """
            addr_list = [i for i in range(self.size)]
            bip44_ctx = Bip44.FromSeed(slip39_seed, Bip44Coins.APTOS)
            for i in range(self.size):
                account = bip44_ctx.Purpose().Coin().Account(i).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
                private_key = account.PrivateKey().Raw().ToBytes()
                aptos_account = APT_Account.load_key(private_key.hex())
                aptos_address = aptos_account.address()
                addr_list[i] = aptos_address
            return addr_list


class count_sui_address:

    def __init__(self, size=10, slip39_seed=""):
        self.size = size
        self.bip44_address = self._from_mnemonic_bip44hdwallet_address(slip39_seed)

    def _from_mnemonic_bip44hdwallet_address(self, slip39_seed):
        """
        @param symbol: 币种
        @param account: 用户自定义账户索引
        @param change: False:0, True:1
        @param address: 地址索引
        """
        addr_list = [i for i in range(self.size)]
        for i in range(self.size):
            bip44_def_ctx = Bip44.FromSeed(slip39_seed, Bip44Coins.SUI)
            account = bip44_def_ctx.Purpose().Coin().Account(i).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
            # 获取 Sui 地址
            sui_address = account.PublicKey().ToAddress()
            addr_list[i] = sui_address
        return addr_list


class count_xlm_address:

    def __init__(self, account=0, change=False, size=5, slip39_seed=""):
        self.account = account
        self.change = change
        self.size = size
        self.bip44_address = self._from_mnemonic_xlm_address(slip39_seed)

    def _from_mnemonic_xlm_address(self, slip39_seed):
        """
        @param symbol: 币种
        @param account: 用户自定义账户索引
        @param change: False:0, True:1
        @param address: 地址索引
        """
        addr_list = [i for i in range(self.size)]
        for i in range(self.size):
            path = "m/44'/148'/{index}'".format(index=i)
            bip32_ctx = Bip32Slip10Ed25519.FromSeed(slip39_seed).DerivePath(path)
            # 从密钥生成 Stellar 地址
            if StellarKeypair is None:
                raise RuntimeError("stellar_sdk not installed. Please install it with: pip install stellar-sdk")
            stellar_keypair = StellarKeypair.from_raw_ed25519_seed(bip32_ctx.PrivateKey().Raw().ToBytes())
            stellar_address = stellar_keypair.public_key
            addr_list[i] = stellar_address
        return addr_list


class count_ada_address:

    def __init__(self, size=10, slip39_seed=""):
        """
        使用 SLIP-23 根密钥生成方式（ed25519 cardano seed）并按 CIP-1852 路径派生，
        输出：
        - 带 staking 的 base address
        - 不带 staking 的 enterprise address
        结构与 bip39_address.py 保持一致：
        - 生成路径 m/1852'/1815'/{i}'/0/{x}，其中 i、x ∈ [0,5]
        - 返回列表元素为 { path, address, i, x }
        """
        if Adahdwallet is None:
            raise RuntimeError("pycardano not installed. Please install it with: pip install pycardano")
        self.size = size
        self.slip39_seed = slip39_seed
        self.addresses = self._calc_slip23_base_addresses()
        self.enterprise_addresses = self._calc_slip23_enterprise_addresses()

    def _calc_slip23_base_addresses(self):
        """
        使用 SLIP-23 根密钥派生方式生成 ADA 地址
        SLIP-23: I = HMAC-SHA512(key="ed25519 cardano seed", data=seed)
        """
        from bip_utils.bip.bip32 import Bip32KeyData
        from bip_utils.cardano.bip32 import CardanoIcarusBip32
        import hashlib as _hashlib
        import hmac as _hmac

        seed_bytes = self.slip39_seed if isinstance(self.slip39_seed, (bytes, bytearray)) else bytes.fromhex(self.slip39_seed)
        if len(seed_bytes) == 0:
            raise ValueError("SLIP-39 seed is empty")

        # SLIP-23 根密钥：I = HMAC-SHA512(key="ed25519 cardano seed", data=seed)
        I = _hmac.new(b"ed25519 cardano seed", seed_bytes, _hashlib.sha512).digest()
        IL, IR = I[:32], I[32:64]
        # k = SHA512(IL); clamp
        k = bytearray(_hashlib.sha512(IL).digest())
        k[0] &= 0xF8
        k[31] = (k[31] & 0x1F) | 0x40
        kL = bytes(k[0:32]); kR = bytes(k[32:64])
        priv_ext = kL + kR
        chain_code = IR

        icarus_master_key = CardanoIcarusBip32.FromPrivateKey(priv_ext, key_data=Bip32KeyData(chain_code=chain_code))
        
        addresses = []
        # 生成 i ∈ [0,5], x ∈ [0,5]
        for i in range(6):
            # 每个账户使用自己的 stake key: m/1852'/1815'/{i}'/2/0
            stake_path = f"m/1852'/1815'/{i}'/2/0"
            stake_bip32 = icarus_master_key.DerivePath(stake_path)
            stake_public_key_bytes = stake_bip32.PublicKey().RawCompressed().ToBytes()
            if len(stake_public_key_bytes) > 32:
                stake_public_key_bytes = stake_public_key_bytes[-32:]
            stake_vk = PaymentVerificationKey.from_primitive(stake_public_key_bytes)
            
            for x in range(6):
                # spend: m/1852'/1815'/{i}'/0/{x}
                spend_path = f"m/1852'/1815'/{i}'/0/{x}"
                spend_bip32 = icarus_master_key.DerivePath(spend_path)
                spend_public_key_bytes = spend_bip32.PublicKey().RawCompressed().ToBytes()
                if len(spend_public_key_bytes) > 32:
                    spend_public_key_bytes = spend_public_key_bytes[-32:]
                spend_vk = PaymentVerificationKey.from_primitive(spend_public_key_bytes)
                # 每个账户使用自己的 stake key
                address = str(AdaAddress(spend_vk.hash(), staking_part=stake_vk.hash(), network=Network.MAINNET))
                addresses.append({
                    'path': spend_path,
                    'address': address,
                    'i': i,
                    'x': x,
                })
        return addresses

    def _calc_slip23_enterprise_addresses(self):
        """
        使用 SLIP-23 根密钥派生方式生成 ADA Enterprise Address（无 staking_part）。
        CIP-1852 spend 路径：m/1852'/1815'/{i}'/0/{x}
        """
        from bip_utils.bip.bip32 import Bip32KeyData
        from bip_utils.cardano.bip32 import CardanoIcarusBip32
        import hashlib as _hashlib
        import hmac as _hmac

        seed_bytes = self.slip39_seed if isinstance(self.slip39_seed, (bytes, bytearray)) else bytes.fromhex(self.slip39_seed)
        if len(seed_bytes) == 0:
            raise ValueError("SLIP-39 seed is empty")

        # SLIP-23 根密钥：I = HMAC-SHA512(key="ed25519 cardano seed", data=seed)
        I = _hmac.new(b"ed25519 cardano seed", seed_bytes, _hashlib.sha512).digest()
        IL, IR = I[:32], I[32:64]
        # k = SHA512(IL); clamp
        k = bytearray(_hashlib.sha512(IL).digest())
        k[0] &= 0xF8
        k[31] = (k[31] & 0x1F) | 0x40
        kL = bytes(k[0:32]); kR = bytes(k[32:64])
        priv_ext = kL + kR
        chain_code = IR

        icarus_master_key = CardanoIcarusBip32.FromPrivateKey(priv_ext, key_data=Bip32KeyData(chain_code=chain_code))

        addresses = []
        # 生成 i ∈ [0,5], x ∈ [0,5]
        for i in range(6):
            for x in range(6):
                spend_path = f"m/1852'/1815'/{i}'/0/{x}"
                spend_bip32 = icarus_master_key.DerivePath(spend_path)
                spend_public_key_bytes = spend_bip32.PublicKey().RawCompressed().ToBytes()
                if len(spend_public_key_bytes) > 32:
                    spend_public_key_bytes = spend_public_key_bytes[-32:]
                spend_vk = PaymentVerificationKey.from_primitive(spend_public_key_bytes)

                # Enterprise address：只有 payment part，没有 staking part
                address = str(AdaAddress(spend_vk.hash(), network=Network.MAINNET))
                addresses.append({
                    'path': spend_path,
                    'address': address,
                    'i': i,
                    'x': x,
                })
        return addresses


class count_slip39_ton_address:
    """
    TON地址计算（使用 SLIP-39 种子）
    通过调用 Node.js 脚本 ton_from_seed.js 或使用 tonsdk 来计算地址
    """

    def __init__(self, slip39_seed="", workchain=0, wallet_version=None, size=10):
        """
        @param slip39_seed: SLIP-39 种子（字节或十六进制字符串）
        @param workchain: 工作链ID，0=主网，-1=测试网
        @param wallet_version: 钱包版本，默认 v4r2（如果 tonsdk 可用）
        @param size: 地址数量（目前只生成一个地址）
        """
        # 如果 slip39_seed 是字符串（hex），转换为字节
        if isinstance(slip39_seed, str):
            self.slip39_seed_bytes = bytes.fromhex(slip39_seed)
        else:
            self.slip39_seed_bytes = slip39_seed
        
        self.workchain = workchain
        self.wallet_version = wallet_version
        self.size = size
        self.ton_address = self._from_seed_ton_address()

    def _from_seed_ton_address(self):
        """
        从 SLIP-39 种子生成 TON 地址
        使用 ed25519-hd-key 派生逻辑（与 BIP39 TON 一致）
        """
        try:
            from tonsdk.contract.wallet import WalletV4ContractR2
            from nacl.signing import SigningKey
            import hashlib
            import hmac
            
            # 1. 获取 master key (使用 ed25519-hd-key 的逻辑)
            h = hmac.new(b'ed25519 seed', self.slip39_seed_bytes, hashlib.sha512).digest()
            key = h[:32]
            chain_code = h[32:]
            
            # 2. 派生 m/44'/607'/0'
            path_indices = [0x8000002C, 0x8000025F, 0x80000000]  # 44', 607', 0'
            
            for index in path_indices:
                data = b'\x00' + key + index.to_bytes(4, 'big')
                I = hmac.new(chain_code, data, hashlib.sha512).digest()
                key = I[:32]
                chain_code = I[32:]
            
            # 3. 从私钥生成公钥
            signing_key = SigningKey(key)
            public_key = bytes(signing_key.verify_key)
            
            # 4. 生成 TON V4R2 钱包地址
            # Keystone3 使用的默认 wallet_id 是 0x29a9a317 (698983191)
            wallet = WalletV4ContractR2(
                public_key=public_key,
                private_key=key,
                wc=self.workchain,
                wallet_id=698983191  # 0x29a9a317
            )
            ton_address = wallet.address.to_string(True, True, False)
            
            return [ton_address]
            
        except ImportError as e:
            # tonsdk 或 nacl 未安装，返回空地址
            placeholder = ""
            return [placeholder for _ in range(self.size)]
        except Exception as e:
            # 其他错误，返回空地址
            print(f"TON address generation error: {e}")
            import traceback
            traceback.print_exc()
            placeholder = ""
            return [placeholder for _ in range(self.size)]


class count_cosmos_address:
    def __init__(self, change, external, address_index,slip39_byte_seed=""):
        self.slip39_byte_seed = slip39_byte_seed
        DEFAULT_DERIVATION_PATH = "m/44'/118'/{change}'/{external}/{address_index}".format(change=change,
                                                                                           external=external,
                                                                                           address_index=address_index)
        SCRT_DERIVATION_PATH = "m/44'/529'/{change}'/{external}/{address_index}".format(change=change,
                                                                                        external=external,
                                                                                        address_index=address_index)
        CRO_DERIVATION_PATH = "m/44'/394'/{change}'/{external}/{address_index}".format(change=change, external=external,
                                                                                       address_index=address_index)
        IOV_DERIVATION_PATH = "m/44'/234'/{change}'/{external}/{address_index}".format(change=change, external=external,
                                                                                       address_index=address_index)
        BLD_DERIVATION_PATH = "m/44'/564'/{change}'/{external}/{address_index}".format(change=change, external=external,
                                                                                       address_index=address_index)
        ETH_DERIVATION_PATH = "m/44'/60'/{change}'/{external}/{address_index}".format(change=change, external=external,
                                                                                      address_index=address_index)
        KAVA_DERIVATION_PATH = "m/44'/459'/{change}'/{external}/{address_index}".format(change=change,
                                                                                        external=external,
                                                                                        address_index=address_index)
        TERRA_DERIVATION_PATH = "m/44'/330'/{change}'/{external}/{address_index}".format(change=change,
                                                                                         external=external,
                                                                                         address_index=address_index)
        RUNE_DERIVATION_PATH = "m/44'/931'/{change}'/{external}/{address_index}".format(change=change,
                                                                                        external=external,
                                                                                        address_index=address_index)
        BABY_BECH32_HRP='bbn'
        NTMPI__BECH32_HRP='neutaro'
        TIA_BECH32_HRP = "celestia"
        NTRN_BECH32_HRP='neutron'
        OSMO_BECH32_HRP = "osmo"
        INJ_BECH32_HRP = "inj"
        ATOM_BECH32_HRP = "cosmos"
        CRO_BECH32_HRP = "cro"
        RUNE_BECH32_HRP = "thor"
        KAVA_BECH32_HRP = "kava"
        LUNC_BECH32_HRP = "terra"
        AXL_BECH32_HRP = "axelar"
        LUNA_BECH32_HRP = "terra"
        AKT_BECH32_HRP = "akash"
        STRD_BECH32_HRP = "stride"
        SCRT_BECH32_HRP = "secret"
        BLD_BECH32_HRP = "agoric"
        CTK_BECH32_HRP = "shentu"
        EVMOS_BECH32_HRP = "evmos"
        STARS_BECH32_HRP = "stars"
        XPRT_BECH32_HRP = "persistence"
        SOMM_BECH32_HRP = "somm"
        JUNO_BECH32_HRP = "juno"
        IRIS_BECH32_HRP = "iaa"
        DVPN_BECH32_HRP = "sent"
        ROWAN__BECH32_HRP = "sif"
        REGEN_BECH32_HRP = "regen"
        BOOT_BECH32_HRP = "bostrom"
        GRAV_BECH32_HRP = "gravity"
        IXO_BECH32_HRP = "ixo"
        NGM_BECH32_HRP = "emoney"
        IOV_BECH32_HRP = "star"
        UMEE_BECH32_HRP = "umee"
        QCK_BECH32_HRP = "quick"
        TGD_BECH32_HRP = "tgrade"
        DYM_BECH32_HRP = "dym"
        def derive_privkey_from_path(seed_bytes, coin_type, change, external, address_index):
            """Derive private key from seed using BIP44 path"""
            # Use Bip32Slip10Secp256k1 for Cosmos-based chains (Secp256k1 curve)
            from bip_utils import Bip32Slip10Secp256k1
            path = f"m/44'/{coin_type}'/{change}'/{external}/{address_index}"
            bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
            account = bip32_ctx.DerivePath(path)
            return account.PrivateKey().Raw().ToBytes()
        
        self.cosmos_privkey = derive_privkey_from_path(self.slip39_byte_seed, 118, change, external, address_index)
        self.cosmos_pubkey = privkey_to_pubkey(self.cosmos_privkey)
        # INJ/DYM/EVMOS：使用 ETH 路径 m/44'/60'/{change}'/{external}/{address_index}
        # 直接从未压缩公钥计算 EVM 20-byte 地址，再做 bech32 编码，不依赖 pyinjective
        from bip_utils import Bip32Slip10Secp256k1
        from eth_hash.auto import keccak
        eth_path = f"m/44'/60'/{change}'/{external}/{address_index}"
        eth_ctx = Bip32Slip10Secp256k1.FromSeed(self.slip39_byte_seed).DerivePath(eth_path)
        eth_pub_uncompressed = eth_ctx.PublicKey().RawUncompressed().ToBytes()[1:]
        evm_addr_bytes = keccak(eth_pub_uncompressed)[-20:]
        evm_5bit_data = bech32.convertbits(evm_addr_bytes, 8, 5, True)
        self.cro_privkey = derive_privkey_from_path(self.slip39_byte_seed, 394, change, external, address_index)
        self.cro_pubkey = privkey_to_pubkey(self.cro_privkey)
        # KAVA - coin type 459
        self.kava_privkey = derive_privkey_from_path(self.slip39_byte_seed, 459, change, external, address_index)
        self.kava_pubkey = privkey_to_pubkey(self.kava_privkey)
        # LUNC/TERRA - coin type 330
        self.lunc_privkey = derive_privkey_from_path(self.slip39_byte_seed, 330, change, external, address_index)
        self.lunc_pubkey = privkey_to_pubkey(self.lunc_privkey)
        # SCRT (Secret Network) - coin type 529
        self.scrt_privkey = derive_privkey_from_path(self.slip39_byte_seed, 529, change, external, address_index)
        self.scrt_pubkey = privkey_to_pubkey(self.scrt_privkey)
        # IOV - coin type 234
        self.iov_privkey = derive_privkey_from_path(self.slip39_byte_seed, 234, change, external, address_index)
        self.iov_pubkey = privkey_to_pubkey(self.iov_privkey)
        # BLD (Agoric) - coin type 564
        self.bld_privkey = derive_privkey_from_path(self.slip39_byte_seed, 564, change, external, address_index)
        self.bld_pubkey = privkey_to_pubkey(self.bld_privkey)
        # RUNE (THORChain) - coin type 931
        self.rune_privkey = derive_privkey_from_path(self.slip39_byte_seed, 931, change, external, address_index)
        self.rune_pubkey = privkey_to_pubkey(self.rune_privkey)

        self.baby_address = pubkey_to_address(self.cosmos_pubkey, hrp=BABY_BECH32_HRP)
        self.neutaro_address = pubkey_to_address(self.cosmos_pubkey, hrp=NTMPI__BECH32_HRP)
        self.tia_address = pubkey_to_address(self.cosmos_pubkey, hrp=TIA_BECH32_HRP)
        self.ntur_address = pubkey_to_address(self.cosmos_pubkey, hrp=NTRN_BECH32_HRP)
        self.osmo_address = pubkey_to_address(self.cosmos_pubkey, hrp=OSMO_BECH32_HRP)
        self.inj_address = bech32.bech32_encode(INJ_BECH32_HRP, evm_5bit_data)
        self.atom_address = pubkey_to_address(self.cosmos_pubkey, hrp=ATOM_BECH32_HRP)
        self.cro_address = pubkey_to_address(self.cro_pubkey, hrp=CRO_BECH32_HRP)
        self.rune_address = pubkey_to_address(self.rune_pubkey, hrp=RUNE_BECH32_HRP)
        self.kava_address = pubkey_to_address(self.kava_pubkey, hrp=KAVA_BECH32_HRP)
        self.lunc_address = pubkey_to_address(self.lunc_pubkey, hrp=LUNC_BECH32_HRP)
        self.axl_address = pubkey_to_address(self.cosmos_pubkey, hrp=AXL_BECH32_HRP)
        self.luna_address = pubkey_to_address(self.lunc_pubkey, hrp=LUNA_BECH32_HRP)
        self.akt_address = pubkey_to_address(self.cosmos_pubkey, hrp=AKT_BECH32_HRP)
        self.strd_address = pubkey_to_address(self.cosmos_pubkey, hrp=STRD_BECH32_HRP)
        self.stars_address = pubkey_to_address(self.cosmos_pubkey, hrp=STARS_BECH32_HRP)
        self.xprt_address = pubkey_to_address(self.cosmos_pubkey, hrp=XPRT_BECH32_HRP)
        self.scrt_address = pubkey_to_address(self.scrt_pubkey, hrp=SCRT_BECH32_HRP)
        self.bld_address = pubkey_to_address(self.bld_pubkey, hrp=BLD_BECH32_HRP)
        self.ctk_address = pubkey_to_address(self.cosmos_pubkey, hrp=CTK_BECH32_HRP)
        self.evmos_address = bech32.bech32_encode(EVMOS_BECH32_HRP, evm_5bit_data)
        self.somm_address = pubkey_to_address(self.cosmos_pubkey, hrp=SOMM_BECH32_HRP)
        self.juno_address = pubkey_to_address(self.cosmos_pubkey, hrp=JUNO_BECH32_HRP)
        self.iris_address = pubkey_to_address(self.cosmos_pubkey, hrp=IRIS_BECH32_HRP)
        self.dvpn_address = pubkey_to_address(self.cosmos_pubkey, hrp=DVPN_BECH32_HRP)
        self.rowan_address = pubkey_to_address(self.cosmos_pubkey, hrp=ROWAN__BECH32_HRP)
        self.regen_address = pubkey_to_address(self.cosmos_pubkey, hrp=REGEN_BECH32_HRP)
        self.boot_address = pubkey_to_address(self.cosmos_pubkey, hrp=BOOT_BECH32_HRP)
        self.grav_address = pubkey_to_address(self.cosmos_pubkey, hrp=GRAV_BECH32_HRP)
        self.ixo_address = pubkey_to_address(self.cosmos_pubkey, hrp=IXO_BECH32_HRP)
        self.ngm_address = pubkey_to_address(self.cosmos_pubkey, hrp=NGM_BECH32_HRP)
        self.iov_address = pubkey_to_address(self.iov_pubkey, hrp=IOV_BECH32_HRP)
        self.umee_address = pubkey_to_address(self.cosmos_pubkey, hrp=UMEE_BECH32_HRP)
        self.qck_address = pubkey_to_address(self.cosmos_pubkey, hrp=QCK_BECH32_HRP)
        self.tgd_address = pubkey_to_address(self.cosmos_pubkey, hrp=TGD_BECH32_HRP)
        self.dym_address = bech32.bech32_encode(DYM_BECH32_HRP, evm_5bit_data)

class count_iota_address:

    def __init__(self, account=0, size=10, slip39_seed=""):
        self.account = account
        self.size = size
        self.bip44_address = self._from_slip39_iota_address(slip39_seed)

    def _from_slip39_iota_address(self, slip39_seed):
        """
        IOTA 地址计算（基于 SLIP-39 种子）
        派生路径: m/44'/4218'/{account}'/0'/0'
        公钥: Ed25519 压缩公钥取后 32 字节
        地址: BLAKE2b-256(raw32) -> 0x 前缀十六进制
        """
        addr_list = [i for i in range(self.size)]
        for i in range(self.size):
            account_index = self.account + i
            path = "m/44'/4218'/{account}'/0'/0'".format(account=account_index)
            bip32_ctx = Bip32Slip10Ed25519.FromSeed(slip39_seed).DerivePath(path)
            pub = bip32_ctx.PublicKey()
            raw_bytes = pub.RawCompressed().ToBytes()
            if len(raw_bytes) > 32:
                raw_bytes = raw_bytes[-32:]
            if len(raw_bytes) != 32:
                raise ValueError(f"期望 32 字节 Ed25519 公钥，但得到 {len(raw_bytes)} 字节")
            h = hashlib.blake2b(digest_size=32)
            h.update(raw_bytes)
            hashed = h.digest()
            addr_list[i] = "0x" + hashed.hex()
        return addr_list

class count_slip39_arweave_address:

    def __init__(self, slip39_seed="", size=1):
        """
        Arweave 地址计算（基于 SLIP-39 种子）
        与 BIP39 版本保持一致：
          1) Rust FFI 生成 (p, q)
          2) 计算 n = p * q
          3) 对 n 的大端字节做 SHA-256
          4) Base64URL（无填充）作为地址
        """
        # 允许 hex 字符串或字节输入
        if isinstance(slip39_seed, str):
            self.slip39_seed_bytes = bytes.fromhex(slip39_seed)
        else:
            self.slip39_seed_bytes = slip39_seed
        self.size = size
        self.arweave_address = self._from_seed_arweave_address()

    def _from_seed_arweave_address(self):
        # 延迟导入，避免顶层依赖冲突
        import hashlib as _hashlib
        import base64 as _base64
        try:
            from .bip39_address import get_rsa_primes_from_rust, int_to_be_bytes
        except ImportError:
            from bip39_address import get_rsa_primes_from_rust, int_to_be_bytes
        # 与 BIP39 流程保持一致：直接把 recover 得到的字节种子传给 Rust（Rust 内部已做双重 SHA-256）
        seed_for_rust = self.slip39_seed_bytes
        if not isinstance(seed_for_rust, (bytes, bytearray)):
            raise TypeError("slip39 seed must be bytes or bytearray")
        if len(seed_for_rust) == 0:
            raise ValueError("slip39 seed is empty")
        addr_list = []
        for _ in range(self.size):
            # 1) 通过 Rust FFI 生成 RSA 素数
            p, q = get_rsa_primes_from_rust(seed_for_rust, verbose=False)
            # 2) 计算 modulus n
            n = p * q
            # 3) 转为大端字节后做 SHA-256
            n_bytes = int_to_be_bytes(n)
            hasher = _hashlib.sha256()
            hasher.update(n_bytes)
            hash_bytes = hasher.digest()
            # 4) Base64URL 无填充
            address = _base64.urlsafe_b64encode(hash_bytes).decode("ascii").rstrip("=")
            addr_list.append(address)
        return addr_list


class count_zec_address:
    """
    ZEC 地址计算（基于 SLIP-39 种子，Keystone 工作流）
    - Seed Fingerprint: BLAKE2b(seed)（类似 MFP）
    - Key Generation: ZIP32 USK 路径 32'/133'/{account}'
      - USK 内含 Transparent K1 扩展私钥 与 Orchard Spending Key
      - 由 USK 生成 UFVK（Unified Full Viewing Key）
    - Address: 由 UFVK 生成 Unified Address（取第 0 个组件集：含透明 + orchard）
    说明：本实现使用延迟导入，若缺少相关依赖，将优雅回退并提示安装步骤。
    """

    def __init__(self, slip39_seed="", account: int = 0):
        """
        @param slip39_seed: SLIP-39 种子（字节或十六进制字符串）
        @param account: 账户索引，默认为 0
        """
        # 如果 slip39_seed 是字符串（hex），转换为字节
        if isinstance(slip39_seed, str):
            self.seed = bytes.fromhex(slip39_seed)
        else:
            self.seed = slip39_seed
        
        if len(self.seed) == 0:
            raise ValueError("SLIP-39 seed is empty")
        
        self.account = account
        self.transparent_address = self._derive_transparent_address()
        self.unified_address = self._derive_unified_address_zip32()

    def _derive_addresses(self):
        t_addr = self._derive_transparent_address()
        u_addr = self._derive_unified_address_zip32()
        return u_addr, t_addr

    def _derive_transparent_address(self) -> str:
        """使用 BIP44 透明地址，m/44'/133'/{account}'/0/0"""
        account_ctx = Bip44.FromSeed(self.seed, Bip44Coins.ZCASH).Purpose().Coin().Account(self.account)
        change_ctx = account_ctx.Change(Bip44Changes.CHAIN_EXT)
        return change_ctx.AddressIndex(0).PublicKey().ToAddress()

    def _derive_unified_address_zip32(self) -> str:
        """
        基于 ZIP32 生成 USK -> UFVK -> UA（第 0 个），路径：32'/133'/{account}'
        依赖：与给定 Rust 代码等价的 Python 绑定：
        - from zcash_vendor_py import derive_ufvk, ufvk_default_address
          - derive_ufvk(params: str, seed: bytes, account_path: str) -> str (UFVK 编码字符串)
          - ufvk_default_address(ufvk: str, params: str) -> str (UA 编码字符串，默认第 0 个/AllAvailableKeys)
        """
        # 延迟导入，便于在未安装时给出清晰错误
        try:
            from zcash_vendor_py import derive_ufvk, ufvk_default_address
        except ImportError:
            # 若无 Python 绑定，改为调用外部命令（用于交叉验证的独立实现）
            # 通过环境变量 ZEC_UA_CMD 指定可执行命令。
            # 期望该命令接受两个参数：<seed_hex> <account_path>，stdout 输出 UA 字符串。
            cmd = os.environ.get("ZEC_UA_CMD")
            seed_hex = self.seed.hex()
            path = f"m/32'/133'/{self.account}'"

            if not cmd:
                rust_manifest = os.path.abspath(
                    os.path.join(
                        os.path.dirname(__file__),
                        "..",
                        "keystone3-firmware",
                        "rust",
                        "apps",
                        "zcash",
                        "Cargo.toml",
                    )
                )
                if not os.path.exists(rust_manifest):
                    raise ImportError("未找到 zcash_vendor_py，且 Rust ZEC example 不存在，无法生成 UA。")
                cmd = [
                    "cargo",
                    "run",
                    "--quiet",
                    "--manifest-path",
                    rust_manifest,
                    "--example",
                    "print_address",
                    "--",
                    seed_hex,
                    path,
                ]
            else:
                cmd = [cmd, seed_hex, path]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True
                )
            except Exception as e:
                raise RuntimeError(f"外部 UA 命令执行失败: {e}")
            ua_out = (result.stdout or "").strip()
            if not ua_out:
                raise RuntimeError("外部 UA 命令未返回任何输出")
            return ua_out

        # ZIP32 路径：32'/133'/{account}'
        path = f"m/32'/133'/{self.account}'"
        # 与 Rust derive_ufvk 等价：返回 UFVK 编码字符串（uview...）
        ufvk = derive_ufvk(params="main", seed=self.seed, account_path=path)
        # 与 Rust ufvk.default_address(AllAvailableKeys).encode(params) 等价：返回 UA（u1...）
        ua_addr = ufvk_default_address(ufvk, params="main")
        return ua_addr


if __name__ == "__main__":
    import os

    bip39_test_mnemonic = os.environ.get("BIP39_MNEMONIC")
    slip39_test_mnemonic = os.environ.get("SLIP39_MNEMONIC")
    test_passphrase = os.environ.get("SLIP39_PASSPHRASE", "")
    if not slip39_test_mnemonic:
        raise SystemExit("Set SLIP39_MNEMONIC before running this script.")
    slip39_test_byte_seed = slip39_menmonic_to_byte_seed(mnemonic=slip39_test_mnemonic, passphrase=test_passphrase)
    slip39_btc_address = count_btc_address(slip39_seed=slip39_test_byte_seed)
    slip39_eth_address = count_eth_address(slip39_seed=slip39_test_byte_seed)
    slip39_trx_address = count_trx_address(slip39_seed=slip39_test_byte_seed)
    slip39_dash_address = count_dash_address(slip39_seed=slip39_test_byte_seed)
    slip39_doge_address = count_doge_address(slip39_seed=slip39_test_byte_seed)
    slip39_ltc_address = count_ltc_address(slip39_seed=slip39_test_byte_seed)
    slip39_xrp_address = count_xrp_address(slip39_seed=slip39_test_byte_seed)
    slip39_bch_address = count_bch_address(slip39_seed=slip39_test_byte_seed)
    slip39_apt_address = count_apt_address(slip39_seed=slip39_test_byte_seed)
    #slip39_seed_extend = hmac.new(b"ed25519 seed",  slip39_test_byte_seed, hashlib.sha512).digest()
    slip39_sol_address = count_solana_address(size=10, slip39_seed=slip39_test_byte_seed)
    xml_address = count_xlm_address(slip39_seed=slip39_test_byte_seed)
    sui_address=count_sui_address(slip39_seed=slip39_test_byte_seed)
    iota_address = count_iota_address(slip39_seed=slip39_test_byte_seed)
    arweave_address = count_slip39_arweave_address(slip39_seed=slip39_test_byte_seed)
    cosmos_address = count_cosmos_address(slip39_byte_seed=slip39_test_byte_seed, change=0, external=0, address_index=0)
    print("---------------BTC---------------")
    for index in range(slip39_btc_address.size):
        print("Address-%d" % index, slip39_btc_address.seed_slip84_address[index], "    ", slip39_btc_address.seed_slip86_address[index], "  ",
              slip39_btc_address.seed_slip49_address[index], "    ", slip39_btc_address.seed_slip44_address[index])
    print("---------------BTC xpub---------------")
    print(slip39_btc_address.seed_slip84_public_key, "    ", slip39_btc_address.seed_slip86_xpublic_key, "    ",
          slip39_btc_address.seed_slip49_public_key, "    ", slip39_btc_address.seed_slip44_xpublic_key)
    print("---------------BTC Multisig xpub---------------")
    for item in slip39_btc_address.multisig_xpubs:
        print(item["script"], "   ", item["path"], "   ", item["xpub"])

    slip39_btc_test_address = count_btc_address(slip39_seed=slip39_test_byte_seed, testnet=True)
    print("---------------BTC TEST地址---------------")
    print("%-9s %-44s %-62s %-36s %s" % ("", "BIP84(Native SegWit)", "BIP86(Taproot)", "BIP49(Nested SegWit)", "BIP44(Legacy)"))
    for index in range(slip39_btc_test_address.size):
        print("Address-%d" % index, slip39_btc_test_address.seed_slip84_address[index], "    ", slip39_btc_test_address.seed_slip86_address[index], "  ",
              slip39_btc_test_address.seed_slip49_address[index], "    ", slip39_btc_test_address.seed_slip44_address[index])
    print("---------------BTC TEST xpub---------------")
    print(slip39_btc_test_address.seed_slip84_public_key, "    ", slip39_btc_test_address.seed_slip86_xpublic_key, "    ",
          slip39_btc_test_address.seed_slip49_public_key, "    ", slip39_btc_test_address.seed_slip44_xpublic_key)
    print("---------------BTC TEST Multisig xpub---------------")
    for item in slip39_btc_test_address.multisig_xpubs:
        print(item["script"], "   ", item["path"], "   ", item["xpub"])

    print("---------------ETH---------------")
    for index in range(slip39_eth_address.size):
        print("Account-%d" % (index + 1), slip39_eth_address.seed_slip44_address[index], "    ",
              slip39_eth_address.seed_ledger_live_address[index], "    ",
              slip39_eth_address.seed_ledger_legacy_address[index])
    print("---------------SOL---------------")
    for index in range(slip39_sol_address.size):
        print("Account-%d" % (index + 1), slip39_sol_address.account_based_path_address[index], "      ",
              slip39_sol_address.single_account_path_address, "      ",
              slip39_sol_address.sub_account_path_address[index])
    # SOL public key for specific paths
    print("---------------SOL PublicKey---------------")
    bip44_sol = Bip44.FromSeed(slip39_test_byte_seed, Bip44Coins.SOLANA)
    sol_account_key = bip44_sol.Purpose().Coin().Account(0)
    sol_sub_key = sol_account_key.Change(Bip44Changes.CHAIN_EXT)
    sol_pk_account = Keypair.from_seed(sol_account_key.PrivateKey().Raw().ToBytes()).pubkey()
    sol_pk_sub = Keypair.from_seed(sol_sub_key.PrivateKey().Raw().ToBytes()).pubkey()
    print(f"m/44'/501'/0'    pubkey(hex): {bytes(sol_pk_account).hex()}")
    print(f"m/44'/501'/0'/0' pubkey(hex): {bytes(sol_pk_sub).hex()}")
    print("---------------XRP---------------")
    for index in range(slip39_xrp_address.size):
        print("Account-%d" % (index + 1), slip39_xrp_address.xrp_slip39_address[index])
    ada_address = count_ada_address(slip39_seed=slip39_test_byte_seed)
    print("---------------ADA---------------")
    for i in range(6):
        print(f"\nm/1852'/1815'/{i}'/0/ 下的地址:")
        print("-" * 80)
        for x in range(5):
            addr_info = next((a for a in ada_address.addresses if a['i'] == i and a['x'] == x), None)
            if addr_info:
                print(f"  [{x}] {addr_info['path']}")
                print(f"      {addr_info['address']}")
    print("-----------ADA Enterprise---------")
    for i in range(6):
        print(f"\nm/1852'/1815'/{i}'/0/ 下的企业地址:")
        print("-" * 80)
        for x in range(5):
            addr_info = next((a for a in ada_address.enterprise_addresses if a['i'] == i and a['x'] == x), None)
            if addr_info:
                print(f"  [{x}] {addr_info['path']}")
                print(f"      {addr_info['address']}")
    slip39_ton_address = count_slip39_ton_address(slip39_seed=slip39_test_byte_seed)
    print("---------------TON---------------")
    print("Address-0", slip39_ton_address.ton_address[0])
    # ZEC 地址（Keystone 工作流）
    try:
        zec_address = count_zec_address(slip39_seed=slip39_test_byte_seed, account=0)
        print("---------------ZEC---------------")
        print("t-addr:", zec_address.transparent_address)
        print("u-addr:", zec_address.unified_address)
    except Exception as e:
        print("---------------ZEC---------------")
        print("ZEC 生成失败:", e)
    print("---------------TRX---------------")
    for index in range(slip39_trx_address.size):
        print("Account-%d" % (index + 1), slip39_trx_address.trx_slip39_address[index])
    print("---------------LTC地址 (BIP44 Legacy P2PKH)---------------")
    for index in range(slip39_ltc_address.size):
        print("Account-%d" % (index + 1), slip39_ltc_address.ltc_slip44_address[index])
    print("---------------LTC地址 (BIP49 P2SH-SegWit)---------------")
    for index in range(slip39_ltc_address.size):
        print("Account-%d" % (index + 1), slip39_ltc_address.ltc_slip49_address[index])
    print("---------------LTC地址 (BIP84 Native SegWit - ltc1开头)---------------")
    for index in range(slip39_ltc_address.size):
        print("Account-%d" % (index + 1), slip39_ltc_address.ltc_slip84_address[index])
    print("---------------BCH---------------")
    for index in range(slip39_bch_address.size):
        print("Account-%d" % (index + 1), slip39_bch_address.bch_slip39_address[index])
    print("---------------DOGE---------------")
    for index in range(slip39_doge_address.size):
        print("Account-%d" % (index + 1), slip39_doge_address.doge_slip39_address[index])
    avax_address = count_avax_address(slip39_seed=slip39_test_byte_seed)
    print("---------------AVAX地址---------------")
    for index in range(avax_address.size):
        # 只输出 X 链地址（bech32 avax...）
        print("Account-%d" % (index + 1), avax_address.avax_address[index])
    print("---------------APT---------------")
    for index in range(slip39_apt_address.size):
        print("Account-%d" % (index + 1), slip39_apt_address.bip44_address[index])
    print("---------------SUI--------------")
    for index in range(sui_address.size):
        print("Account-%d" % (index + 1), sui_address.bip44_address[index])
    print("---------------IOTA---------------")
    for index in range(iota_address.size):
        print("Account-%d" % (index + 1), iota_address.bip44_address[index])
    print("---------------DASH---------------")
    for index in range(slip39_dash_address.size):
        print("Account-%d" % (index + 1), slip39_dash_address.dash_slip39_address[index])
    print("---------------ARWEAVE---------------")
    print("Address-0", arweave_address.arweave_address[0])
    print("---------------XLM---------------")
    for index in range(xml_address.size):
        print("Account-%d" % (index + 1), xml_address.bip44_address[index])
    print("---------------BABY---------------")
    print(cosmos_address.baby_address)
    print("---------------NTMPI---------------")
    print(cosmos_address.neutaro_address)
    print("---------------TIA---------------")
    print(cosmos_address.tia_address)
    print("---------------NTUR---------------")
    print(cosmos_address.ntur_address)
    print("---------------DYM---------------")
    print(cosmos_address.dym_address)
    print("---------------OSMO---------------")
    print(cosmos_address.osmo_address)
    print("---------------INJ---------------")
    print(cosmos_address.inj_address)
    print("---------------ATOM---------------")
    print(cosmos_address.atom_address)
    print("---------------CRO--------------")
    print(cosmos_address.cro_address)
    print("---------------RUNE--------------")
    print(cosmos_address.rune_address)
    print("---------------KAVA--------------")
    print(cosmos_address.kava_address)
    print("---------------LUNC--------------")
    print(cosmos_address.lunc_address)
    print("---------------axl---------------")
    print(cosmos_address.axl_address)
    print("---------------luna---------------")
    print(cosmos_address.luna_address)
    print("---------------akt---------------")
    print(cosmos_address.akt_address)
    print("---------------strd---------------")
    print(cosmos_address.strd_address)
    print("---------------scrt---------------")
    print(cosmos_address.scrt_address)
    print("---------------bld---------------")
    print(cosmos_address.bld_address)
    print("---------------ctk---------------")
    print(cosmos_address.ctk_address)
    print("---------------evmos---------------")
    print(cosmos_address.evmos_address)
    print("---------------stars---------------")
    print(cosmos_address.stars_address)
    print("---------------xprt---------------")
    print(cosmos_address.xprt_address)
    print("---------------somm---------------")
    print(cosmos_address.somm_address)
    print("---------------juno--------------")
    print(cosmos_address.juno_address)
    print("---------------iris--------------")
    print(cosmos_address.iris_address)
    print("---------------dvpn--------------")
    print(cosmos_address.dvpn_address)
    print("---------------rowan---------------")
    print(cosmos_address.rowan_address)
    print("---------------regen---------------")
    print(cosmos_address.regen_address)
    print("---------------boot---------------")
    print(cosmos_address.boot_address)
    print("---------------grav---------------")
    print(cosmos_address.grav_address)
    print("---------------ixo--------------")
    print(cosmos_address.ixo_address)
    print("---------------ngm--------------")
    print(cosmos_address.ngm_address)
    print("---------------iov--------------")
    print(cosmos_address.iov_address)
    print("---------------umee--------------")
    print(cosmos_address.umee_address)
    print("---------------qck--------------")
    print(cosmos_address.qck_address)
    print("---------------tgd--------------")
    print(cosmos_address.tgd_address)
