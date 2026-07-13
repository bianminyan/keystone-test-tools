from bip_utils import (
    Bip39SeedGenerator,
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
    Bip39Languages,
)
import os
# Monero 地址生成需要 nacl 库
from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp
NACL_AVAILABLE = True
from bip_utils.cardano.bip32 import CardanoIcarusBip32
from bip_utils.cardano.mnemonic import CardanoIcarusSeedGenerator

# 可选依赖
try:
    from solders.keypair import Keypair as SoldersKeypair
    SOLDERS_AVAILABLE = True
except ImportError:
    SoldersKeypair = None
    SOLDERS_AVAILABLE = False

try:
    from stellar_sdk import Keypair as StellarKeypair
    STELLAR_AVAILABLE = True
except ImportError:
    StellarKeypair = None
    STELLAR_AVAILABLE = False

try:
    from aptos_sdk.account import Account
    APTOS_AVAILABLE = True
except ImportError:
    Account = None
    APTOS_AVAILABLE = False

try:
    from cosmospy import pubkey_to_address, privkey_to_pubkey, seed_to_privkey
    COSMOSPY_AVAILABLE = True
except ImportError:
    pubkey_to_address = None
    privkey_to_pubkey = None
    seed_to_privkey = None
    COSMOSPY_AVAILABLE = False

try:
    from pycardano.address import Address as AdaAddress
    from pycardano.crypto.bip32 import HDWallet as Adahdwallet
    from pycardano.key import PaymentVerificationKey
    from pycardano.network import Network
    PYCARDANO_AVAILABLE = True
except ImportError:
    PYCARDANO_AVAILABLE = False
    AdaAddress = None
    Adahdwallet = None
    PaymentVerificationKey = None
    Network = None

try:
    from pysui.abstracts.client_keypair import SignatureScheme
    from pysui.sui import sui_crypto
    PYSUI_AVAILABLE = True
except ImportError:
    SignatureScheme = None
    sui_crypto = None
    PYSUI_AVAILABLE = False

try:
    from pyinjective import PrivateKey as INJPrivateKey
    PYINJECTIVE_AVAILABLE = True
except ImportError:
    INJPrivateKey = None
    PYINJECTIVE_AVAILABLE = False

try:
    from tonsdk.contract.wallet import WalletVersionEnum, Wallets
    TONSDK_AVAILABLE = True
except ImportError:
    WalletVersionEnum = None
    Wallets = None
    TONSDK_AVAILABLE = False

try:
    from monero.wallet import Wallet as XMR_Wallet
    from monero.backends.offline import OfflineWallet as XMR_Offline
    MONERO_AVAILABLE = True
except ImportError:
    XMR_Wallet = None
    XMR_Offline = None
    MONERO_AVAILABLE = False
try:
    import base58
    BASE58_AVAILABLE = True
except ImportError:
    base58 = None
    BASE58_AVAILABLE = False

try:
    import bech32
    BECH32_AVAILABLE = True
except ImportError:
    bech32 = None
    BECH32_AVAILABLE = False

try:
    from bip32 import BIP32 as BIP32_Class  # pip install bip32
    BIP32_AVAILABLE = True
except ImportError:
    BIP32_Class = None
    BIP32_AVAILABLE = False

import hashlib
from hashlib import blake2b
import binascii
import subprocess
import os
import hmac
import unicodedata
import base64
import sys
import ctypes
from ctypes import POINTER, Structure, c_uint8, c_uint, c_char_p, c_size_t
from typing import Tuple


def hash160(data: bytes) -> bytes:
    sha_hash = hashlib.sha256(data).digest()
    ripemd = hashlib.new("ripemd160")
    ripemd.update(sha_hash)
    return ripemd.digest()


# 包装 cosmospy 的 seed_to_privkey 以支持 passphrase
def seed_to_privkey_with_passphrase(mnemonic: str, path: str = "m/44'/118'/0'/0/0", passphrase: str = "") -> bytes:
    """
    从助记词生成私钥，真正支持 passphrase
    使用 bip_utils 来正确处理 passphrase
    """
    from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
    import hashlib
    
    # 使用 passphrase 生成 seed
    seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    
    # 使用 BIP32 派生私钥
    bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed)
    
    # 解析路径并派生
    # 路径格式: m/44'/118'/0'/0/0
    path_parts = path.strip().split('/')
    if path_parts[0].lower() != 'm':
        raise ValueError(f"Invalid path: {path}")
    
    for part in path_parts[1:]:
        if part.endswith("'") or part.endswith('h'):
            # 强化派生
            index = int(part[:-1])
            bip32_ctx = bip32_ctx.ChildKey(0x80000000 + index)
        else:
            # 普通派生
            index = int(part)
            bip32_ctx = bip32_ctx.ChildKey(index)
    
    # 返回私钥字节
    return bip32_ctx.PrivateKey().Raw().ToBytes()


class count_btc_address:
    """
    btc地址和xpub计算
    """

    prefixes = {
        "xpub": "0488b21e",
        "ypub": "049d7cb2",
        "Ypub": "0295b43f",
        "zpub": "04b24746",
        "Zpub": "02aa7ed3",
        "tpub": "043587cf",
        "upub": "044a5262",
        "vpub": "045f1cf6",
        "Upub": "024289ef",
        "Vpub": "02575483",
    }

    def __init__(self, mnemonic, passphrase, account=0, change=False, size=10, testnet=False):
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.account = account
        self.change = change
        self.size = size
        self.testnet = testnet
        self.seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)

        bip44_coin = Bip44Coins.BITCOIN_TESTNET if self.testnet else Bip44Coins.BITCOIN
        bip49_coin = Bip49Coins.BITCOIN_TESTNET if self.testnet else Bip49Coins.BITCOIN
        bip84_coin = Bip84Coins.BITCOIN_TESTNET if self.testnet else Bip84Coins.BITCOIN
        bip86_coin = Bip86Coins.BITCOIN_TESTNET if self.testnet else Bip86Coins.BITCOIN

        self._bip44_account = Bip44.FromSeed(self.seed, bip44_coin).Purpose().Coin().Account(self.account)
        self._bip49_account = Bip49.FromSeed(self.seed, bip49_coin).Purpose().Coin().Account(self.account)
        self._bip84_account = Bip84.FromSeed(self.seed, bip84_coin).Purpose().Coin().Account(self.account)
        self._bip86_account = Bip86.FromSeed(self.seed, bip86_coin).Purpose().Coin().Account(self.account)

        self.bip44_address = self._derive_addresses(self._bip44_account)
        self.bip49_address = self._derive_addresses(self._bip49_account)
        self.bip84_address = self._derive_addresses(self._bip84_account)
        self.bip86_address = self._derive_addresses(self._bip86_account)

        self.bip44_xpublic_key = self._bip44_account.PublicKey().ToExtended()
        self.bip49_xpublic_key = self._bip49_account.PublicKey().ToExtended()
        self.bip84_xpublic_key = self._bip84_account.PublicKey().ToExtended()
        # ypub 和 zpub 需要 base58 库
        if base58 is None:
            # 如果 base58 未安装，使用原始的 xpub（不转换版本字节）
            self.bip49_ypublic_key = self.bip49_xpublic_key
            self.bip84_zpublic_key = self.bip84_xpublic_key
        else:
            if self.testnet:
                self.bip49_ypublic_key = self._change_upub_version_bytes(self.bip49_xpublic_key)
                self.bip84_zpublic_key = self._change_vpub_version_bytes(self.bip84_xpublic_key)
            else:
                self.bip49_ypublic_key = self._change_ypub_version_bytes(self.bip49_xpublic_key)
                self.bip84_zpublic_key = self._change_zpub_version_bytes(self.bip84_xpublic_key)
        self.bip86_xpublic_key = self._bip86_account.PublicKey().ToExtended()

    def _derive_addresses(self, account_ctx):
        change_ctx = account_ctx.Change(self._change_enum())
        return [change_ctx.AddressIndex(i).PublicKey().ToAddress() for i in range(self.size)]

    def _change_enum(self):
        return Bip44Changes.CHAIN_INT if self.change else Bip44Changes.CHAIN_EXT

    def _change_ypub_version_bytes(self, extended_key):
        if base58 is None:
            raise RuntimeError("未安装 base58 库，请先安装: pip install base58")
        if extended_key.startswith("ypub") or extended_key.startswith("Ypub"):
            return extended_key
        data = base58.b58decode_check(extended_key.strip())
        converted = bytes.fromhex(count_btc_address.prefixes["ypub"]) + data[4:]
        return base58.b58encode_check(converted).decode()

    def _change_zpub_version_bytes(self, extended_key):
        if base58 is None:
            raise RuntimeError("未安装 base58 库，请先安装: pip install base58")
        if extended_key.startswith("zpub") or extended_key.startswith("Zpub"):
            return extended_key
        data = base58.b58decode_check(extended_key.strip())
        converted = bytes.fromhex(count_btc_address.prefixes["zpub"]) + data[4:]
        return base58.b58encode_check(converted).decode()

    def _change_upub_version_bytes(self, extended_key):
        if base58 is None:
            raise RuntimeError("未安装 base58 库，请先安装: pip install base58")
        if extended_key.startswith("upub") or extended_key.startswith("Upub"):
            return extended_key
        data = base58.b58decode_check(extended_key.strip())
        converted = bytes.fromhex(count_btc_address.prefixes["upub"]) + data[4:]
        return base58.b58encode_check(converted).decode()

    def _change_vpub_version_bytes(self, extended_key):
        if base58 is None:
            raise RuntimeError("未安装 base58 库，请先安装: pip install base58")
        if extended_key.startswith("vpub") or extended_key.startswith("Vpub"):
            return extended_key
        data = base58.b58decode_check(extended_key.strip())
        converted = bytes.fromhex(count_btc_address.prefixes["vpub"]) + data[4:]
        return base58.b58encode_check(converted).decode()

    def count_especial_address(self, address_type, index):
        if address_type == "BIP44":
            return self._derive_single_address(self._bip44_account, index)
        if address_type == "BIP49":
            return self._derive_single_address(self._bip49_account, index)
        if address_type == "BIP84":
            return self._derive_single_address(self._bip84_account, index)
        raise ValueError(f"Unsupported address type: {address_type}")

    def _derive_single_address(self, account_ctx, index):
        change_ctx = account_ctx.Change(self._change_enum())
        return change_ctx.AddressIndex(index).PublicKey().ToAddress()


class count_eth_address:
    """
        ETH地址计算
        """

    def __init__(self, mnemonic, passphrase, account=0, change=False, size=50):
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.account = account
        self.change = change
        self.size = size
        self.seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        self._coin_ctx = Bip44.FromSeed(self.seed, Bip44Coins.ETHEREUM).Purpose().Coin()
        self.bip44_address = self._derive_standard_addresses()
        self.ledger_live_address = self._derive_ledger_live_addresses()
        self.ledger_legacy_address = self._derive_ledger_legacy_addresses()

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

    def __init__(self, mnemonic, passphrase, account=0, change=False, size=50):
        if SoldersKeypair is None:
            raise RuntimeError("未安装 solders 库，请先安装: pip install solders")
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.account = account
        self.change = change
        self.size = size
        self.sub_account_path_address = self._from_mnemonic_sub_account_path_address()
        self.account_based_path_address = self._from_mnemonic_account_based_path_address()
        self.single_account_path_address = self._from_mnemonic_single_account_path_address()

    def _from_mnemonic_sub_account_path_address(self):
        seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        addr_list = [i for i in range(self.size)]
        for i in range(self.size):
            pubkey = SoldersKeypair.from_seed_and_derivation_path(seed, f"m/44'/501'/{i}'/0'").pubkey()
            addr_list[i] = str(pubkey)
        return addr_list

    def _from_mnemonic_account_based_path_address(self):
        seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        addr_list = [i for i in range(self.size)]
        for i in range(self.size):
            pubkey = SoldersKeypair.from_seed_and_derivation_path(seed, f"m/44'/501'/{i}'").pubkey()
            addr_list[i] = str(pubkey)
        return addr_list

    def _from_mnemonic_single_account_path_address(self):
        seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        pubkey = SoldersKeypair.from_seed_and_derivation_path(seed, "m/44'/501'").pubkey()
        address = str(pubkey)
        return address


class count_avax_address:
    """

        """

    def __init__(self, mnemonic, passphrase, account=0, change=False, size=15):
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.account = account
        self.change = change
        self.size = size
        self.seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        self.bip44_address = self._from_mnemonic_bip44_address()
        self.avax_address = self._from_mnemonic_avax_address()

    def _from_mnemonic_bip44_address(self):
        # AVAX P/X 链使用的 BIP44 路径为 m/44'/9000'/X'/0/0
        # 这里按照 X 作为 account 维度来递增：X = account, account+1, ...
        addresses = []
        for acc in range(self.account, self.account + self.size):
            account_ctx = Bip44.FromSeed(self.seed, Bip44Coins.AVAX_X_CHAIN).Purpose().Coin().Account(acc)
            change_ctx = account_ctx.Change(Bip44Changes.CHAIN_INT if self.change else Bip44Changes.CHAIN_EXT)
            # 固定地址索引为 0，对应 m/44'/9000'/X'/0/0
            addresses.append(change_ctx.AddressIndex(0).PublicKey().ToAddress())
        return addresses

    def _from_mnemonic_avax_address(self):
        if bech32 is None:
            raise RuntimeError("未安装 bech32 库，请先安装: pip install bech32")
        address_list = []
        # 同样按照 X 作为 account 维度：对每个 X 取 index=0
        for acc in range(self.account, self.account + self.size):
            account_ctx = Bip44.FromSeed(self.seed, Bip44Coins.AVAX_X_CHAIN).Purpose().Coin().Account(acc)
            change_ctx = account_ctx.Change(Bip44Changes.CHAIN_EXT)
            bip44_address_key = change_ctx.AddressIndex(0)
            public_key = bip44_address_key.PublicKey().RawCompressed().ToBytes()
            address_hash = hash160(public_key)
            address_list.append(bech32.bech32_encode("avax", bech32.convertbits(address_hash, 8, 5)))
        return address_list


class count_tron_address:
    """
    tron地址计算
    """

    def __init__(self, mnemonic, passphrase, account=0, change=False, size=10):
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.account = account
        self.change = change
        self.size = size
        self.seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        self.bip44_address = self._from_mnemonic_bip44_address()

    def _from_mnemonic_bip44_address(self):
        account_ctx = Bip44.FromSeed(self.seed, Bip44Coins.TRON).Purpose().Coin().Account(self.account)
        change_ctx = account_ctx.Change(Bip44Changes.CHAIN_INT if self.change else Bip44Changes.CHAIN_EXT)
        return [change_ctx.AddressIndex(i).PublicKey().ToAddress() for i in range(self.size)]


class count_xrp_address:
    """
       xrp地址计算
       """

    def __init__(self, mnemonic, passphrase, account=0, change=False, size=10):
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.account = account
        self.change = change
        self.size = size
        self.bip44_address = self._from_mnemonic_bip44hdwallet_address()

    def _from_mnemonic_bip44hdwallet_address(self):
        """
        @param symbol: 币种
        @param account: 用户自定义账户索引
        @param change: False:0, True:1
        @param address: 地址索引
        """
        seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        addr_list = [i for i in range(self.size)]
        bip44_ctx = Bip44.FromSeed(seed, Bip44Coins.RIPPLE)
        for i in range(self.size):
            account = bip44_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(i)
            private_key = account.PrivateKey().Raw().ToBytes()
            # 获取公钥并生成 XRP 地址
            public_key = account.PublicKey().RawCompressed().ToBytes()
            xrp_address = XrpAddr.EncodeKey(public_key)
            addr_list[i] = xrp_address
        return addr_list


class count_ada_address:

    def __init__(self, mnemonic, passphrase, size=10):
        if not PYCARDANO_AVAILABLE:
            raise RuntimeError("未安装 pycardano 库，请先安装: pip install pycardano")
        self.size = size
        # 清理助记词：去除多余空格
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.addresses = self.cal_addr()
        # Ledger/BitBox02 地址（使用相同的派生路径）
        self.ledger_bitbox02_addresses = self.cal_ledger_bitbox02_addr()
        # Enterprise Address（无质押功能的地址）
        self.enterprise_addresses = self.cal_enterprise_addr()

    def cal_addr(self):
        """
        生成路径 m/1852'/1815'/{i}'/0/{x} 的地址，其中 i 和 x 都从 0 到 5
        - spend key: m/1852'/1815'/{i}'/0/{x}
        - stake key: m/1852'/1815'/{i}'/2/0 (固定)
        """
        addresses = []
        wallet = Adahdwallet.from_mnemonic(self.mnemonic, self.passphrase)
        
        # i 和 x 都从 0 到 5
        for i in range(6):
            # 每个 i 的 stake key 是固定的：m/1852'/1815'/{i}'/2/0
            stake_wallet = wallet.derive_from_path(f"m/1852'/1815'/{i}'/2/0")
            stake_vk = PaymentVerificationKey.from_primitive(stake_wallet.public_key)
            
            for x in range(6):
                # spend key: m/1852'/1815'/{i}'/0/{x}
                spend_wallet = wallet.derive_from_path(f"m/1852'/1815'/{i}'/0/{x}")
                spend_vk = PaymentVerificationKey.from_primitive(spend_wallet.public_key)
                
                # 生成地址
                address = str(AdaAddress(spend_vk.hash(), staking_part=stake_vk.hash(), network=Network.MAINNET))
                
                addresses.append({
                    'path': f"m/1852'/1815'/{i}'/0/{x}",
                    'address': address,
                    'i': i,
                    'x': x
                })
        
        return addresses
        
    def cal_enterprise_addr(self):
        """
        计算 Enterprise Address (无质押功能的地址)
        路径通常遵循: m/1852'/1815'/{i}'/0/{x}
        """
        ent_addresses = []
        # 这里复用之前的逻辑获取 spend key
        wallet = Adahdwallet.from_mnemonic(self.mnemonic, self.passphrase)
        
        for i in range(6):
            for x in range(6):
                # 1. 派生支出密钥 (Spend Key)
                spend_wallet = wallet.derive_from_path(f"m/1852'/1815'/{i}'/0/{x}")
                spend_vk = PaymentVerificationKey.from_primitive(spend_wallet.public_key)
                
                # 2. 生成 Enterprise Address
                # 关键点：staking_part 设为 None
                ent_address = str(AdaAddress(
                    payment_part=spend_vk.hash(), 
                    staking_part=None, 
                    network=Network.MAINNET
                ))
                
                ent_addresses.append({
                    'path': f"m/1852'/1815'/{i}'/0/{x}",
                    'address': ent_address,
                    'type': 'Enterprise',
                    'i': i,
                    'x': x
                })
        return ent_addresses

    def cal_ledger_bitbox02_addr(self):
        """
        计算 Ledger/BitBox02 方法下的 ADA 地址
        使用 Icarus master key 生成方法
        派生路径: m/1852'/1815'/{i}'/0/{x} (spend) 和 m/1852'/1815'/{i}'/2/0 (stake)
        """
        # 使用 Ledger/BitBox02 的 master key 生成算法
        priv_ext, cc = get_ledger_bitbox02_master_key_by_mnemonic(self.mnemonic, self.passphrase)
        from bip_utils.bip.bip32 import Bip32KeyData
        icarus_master_key = CardanoIcarusBip32.FromPrivateKey(priv_ext, key_data=Bip32KeyData(chain_code=cc))

        addresses = []
        
        # i 和 x 都从 0 到 5
        for i in range(6):
            # Stake key: m/1852'/1815'/{i}'/2/0 (固定)
            stake_bip32 = icarus_master_key.DerivePath(f"m/1852'/1815'/{i}'/2/0")
            stake_public_key_bytes = stake_bip32.PublicKey().RawCompressed().ToBytes()
            if len(stake_public_key_bytes) > 32:
                stake_public_key_bytes = stake_public_key_bytes[-32:]
            stake_vk = PaymentVerificationKey.from_primitive(stake_public_key_bytes)

            for x in range(6):
                # Spend key: m/1852'/1815'/{i}'/0/{x}
                spend_bip32 = icarus_master_key.DerivePath(f"m/1852'/1815'/{i}'/0/{x}")
                spend_public_key_bytes = spend_bip32.PublicKey().RawCompressed().ToBytes()
                # 如果长度>32，取最后32字节
                if len(spend_public_key_bytes) > 32:
                    spend_public_key_bytes = spend_public_key_bytes[-32:]
                spend_vk = PaymentVerificationKey.from_primitive(spend_public_key_bytes)

                # Base address (with staking)
                address = str(AdaAddress(spend_vk.hash(), staking_part=stake_vk.hash(), network=Network.MAINNET))
                
                addresses.append({
                    'path': f"m/1852'/1815'/{i}'/0/{x}",
                    'address': address,
                    'i': i,
                    'x': x
                })

        return addresses


def get_ledger_bitbox02_master_key_by_mnemonic(mnemonic_words: str, passphrase: str):
    # Normalize per BIP-39
    mnemonic_n = unicodedata.normalize("NFKD", mnemonic_words)
    # collapse multiple spaces and trim
    mnemonic_n = " ".join(mnemonic_n.strip().split())
    passphrase_n = unicodedata.normalize("NFKD", passphrase)
    passphrase_bytes = passphrase_n.encode("utf-8")
    salt = b"mnemonic" + passphrase_bytes
    # PBKDF2-HMAC-SHA512 with iterations=2048, dklen=64, password = normalized mnemonic words
    key = hashlib.pbkdf2_hmac("sha512", mnemonic_n.encode("utf-8"), salt, 2048, dklen=64)

    def hmac_sha512_seed(data: bytes) -> bytes:
        return hmac.new(b"ed25519 seed", data, hashlib.sha512).digest()

    # Compute IL, IR
    digest = hmac_sha512_seed(key)
    i_l, i_r = digest[:32], digest[32:64]
    # Repeat until bit 5 of last byte of IL is not set
    while (i_l[31] & 0x20) != 0:
        digest = hmac_sha512_seed(i_l + i_r)
        i_l, i_r = digest[:32], digest[32:64]

    # Ed25519 clamp (as per standard scalar clamping)
    i_l = bytearray(i_l)
    i_l[0] &= 0xF8           # clear lowest 3 bits
    i_l[31] &= 0x7F          # clear highest bit
    i_l[31] |= 0x40          # set second-highest bit
    i_l = bytes(i_l)

    # Chain code: HMAC-SHA256 with key "ed25519 seed" over 0x01 || key
    cc = hmac.new(b"ed25519 seed", b"\x01" + key, hashlib.sha256).digest()
    priv_ext = i_l + i_r
    return priv_ext, cc


class count_ltc_address:
    """
    LTC地址计算，支持 BIP44 (Legacy P2PKH)、BIP49 (P2SH-SegWit)、BIP84 (Native SegWit)
    """

    def __init__(self, mnemonic, passphrase, account=0, change=False, size=10):
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.account = account
        self.change = change
        self.size = size
        self.seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)

        # 初始化各种 BIP 路径的账户上下文
        self._bip44_account = Bip44.FromSeed(self.seed, Bip44Coins.LITECOIN).Purpose().Coin().Account(self.account)
        self._bip49_account = Bip49.FromSeed(self.seed, Bip49Coins.LITECOIN).Purpose().Coin().Account(self.account)
        self._bip84_account = Bip84.FromSeed(self.seed, Bip84Coins.LITECOIN).Purpose().Coin().Account(self.account)

        # 派生地址
        self.bip44_address = self._derive_addresses(self._bip44_account)
        self.bip49_address = self._derive_addresses(self._bip49_account)
        self.bip84_address = self._derive_addresses(self._bip84_account)

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

    def __init__(self, mnemonic, passphrase, account=0, change=False, size=10):
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.account = account
        self.change = change
        self.size = size
        self.seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        self.bip44_address = self._from_mnemonic_bip44_address()

    def _from_mnemonic_bip44_address(self):
        account_ctx = Bip44.FromSeed(self.seed, Bip44Coins.BITCOIN_CASH).Purpose().Coin().Account(self.account)
        change_ctx = account_ctx.Change(Bip44Changes.CHAIN_INT if self.change else Bip44Changes.CHAIN_EXT)
        return [change_ctx.AddressIndex(i).PublicKey().ToAddress() for i in range(self.size)]


class count_apt_address:

    def __init__(self, mnemonic, passphrase, account=0, change=False, size=10):
        if Account is None:
            raise RuntimeError("未安装 aptos_sdk 库，请先安装: pip install aptos-sdk")
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.account = account
        self.change = change
        self.size = size
        self.bip44_address = self._from_mnemonic_bip44hdwallet_address()

    def _from_mnemonic_bip44hdwallet_address(self):
        """
        @param symbol: 币种
        @param account: 用户自定义账户索引
        @param change: False:0, True:1
        @param address: 地址索引
        """
        seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        addr_list = [i for i in range(self.size)]
        bip44_ctx = Bip44.FromSeed(seed, Bip44Coins.APTOS)
        for i in range(self.size):
            account = bip44_ctx.Purpose().Coin().Account(i).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
            private_key = account.PrivateKey().Raw().ToBytes()
            aptos_account = Account.load_key(private_key.hex())
            aptos_address = aptos_account.address()
            addr_list[i] = aptos_address
        return addr_list


class count_sui_address:
    """
    SUI地址计算
    """

    def __init__(self, mnemonic, passphrase, account=0, size=10):
        if not PYSUI_AVAILABLE:
            raise RuntimeError("未安装 pysui 库，请先安装: pip install pysui")
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.account = account
        self.size = size
        self.sui_addr = self._from_mnemonic_sui_address()

    def _from_mnemonic_sui_address(self):
        """
        @param mnemonic: 助记词
        @param passphrase: 密码短语
        @param account: 起始账户索引
        @param size: 地址数量
        """
        # 使用 Bip39SeedGenerator 生成 seed（与 IOTA 保持一致）
        seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        addr_list = [i for i in range(self.size)]
        for i in range(self.size):
            # SUI 派生路径: m/44'/784'/{account}'/0'/0'
            account_index = self.account + i
            path = "m/44'/784'/{account}'/0'/0'".format(account=account_index)
            bip32_ctx = Bip32Slip10Ed25519.FromSeed(seed).DerivePath(path)
            # 获取32字节Ed25519公钥（与 IOTA 保持一致）
            pub = bip32_ctx.PublicKey()
            raw_bytes = pub.RawCompressed().ToBytes()
            # 如果长度>32，取最后32字节
            if len(raw_bytes) > 32:
                raw_bytes = raw_bytes[-32:]
            if len(raw_bytes) != 32:
                raise ValueError(f"期望 32 字节 Ed25519 公钥，但得到 {len(raw_bytes)} 字节")
            # SUI 地址计算逻辑：
            # 1. 在公钥前插入签名方案标志字节（Ed25519 = 0x00）
            buf = bytes([0x00]) + raw_bytes
            # 2. BLAKE2b-256 哈希
            h = blake2b(digest_size=32)
            h.update(buf)
            hashed = h.digest()
            # 3. 返回带0x前缀的十六进制地址
            addr_list[i] = "0x" + hashed.hex()
        return addr_list


class count_dash_address:
    """
    P2PKH地址类型
    """

    def __init__(self, mnemonic, passphrase, account=0, change=False, size=10):
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.account = account
        self.change = change
        self.size = size
        self.seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        self.bip44_address = self._from_mnemonic_bip44_address()

    def _from_mnemonic_bip44_address(self):
        account_ctx = Bip44.FromSeed(self.seed, Bip44Coins.DASH).Purpose().Coin().Account(self.account)
        change_ctx = account_ctx.Change(Bip44Changes.CHAIN_INT if self.change else Bip44Changes.CHAIN_EXT)
        return [change_ctx.AddressIndex(i).PublicKey().ToAddress() for i in range(self.size)]


class count_doge_address:
    """
    DOGE地址计算
    """

    def __init__(self, mnemonic, passphrase, account=0, change=False, size=10):
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.account = account
        self.change = change
        self.size = size
        self.seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        self.bip44_address = self._from_mnemonic_bip44_address()

    def _from_mnemonic_bip44_address(self):
        account_ctx = Bip44.FromSeed(self.seed, Bip44Coins.DOGECOIN).Purpose().Coin().Account(self.account)
        change_ctx = account_ctx.Change(Bip44Changes.CHAIN_INT if self.change else Bip44Changes.CHAIN_EXT)
        return [change_ctx.AddressIndex(i).PublicKey().ToAddress() for i in range(self.size)]



class count_xlm_address:

    def __init__(self, mnemonic, passphrase, account=0, change=False, size=5):
        if StellarKeypair is None:
            raise RuntimeError("未安装 stellar_sdk 库，请先安装: pip install stellar-sdk")
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.account = account
        self.change = change
        self.size = size
        self.bip44_address = self._from_mnemonic_xlm_address()

    def _from_mnemonic_xlm_address(self):
        """
        @param symbol: 币种
        @param account: 用户自定义账户索引
        @param change: False:0, True:1
        @param address: 地址索引
        """
        seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        addr_list = [i for i in range(self.size)]
        for i in range(self.size):
            path = "m/44'/148'/{index}'".format(index=i)
            bip32_ctx = Bip32Slip10Ed25519.FromSeed(seed).DerivePath(path)
            # 从密钥生成 Stellar 地址
            stellar_keypair = StellarKeypair.from_raw_ed25519_seed(bip32_ctx.PrivateKey().Raw().ToBytes())
            stellar_address = stellar_keypair.public_key
            addr_list[i] = stellar_address
        return addr_list


class count_iota_address:
    """
    IOTA地址计算
    """

    def __init__(self, mnemonic, passphrase, account=0, size=10):
        self.mnemonic = mnemonic
        self.passphrase = passphrase
        self.account = account
        self.size = size
        self.bip44_address = self._from_mnemonic_iota_address()

    def _from_mnemonic_iota_address(self):
        """
        @param mnemonic: 助记词
        @param passphrase: 密码短语
        @param account: 起始账户索引
        @param size: 地址数量
        """

        seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        addr_list = [i for i in range(self.size)]
        for i in range(self.size):
            # IOTA 派生路径: m/44'/4218'/{account}'/0'/0'
            # 每个账户对应一个地址，使用不同的account索引生成多个地址
            account_index = self.account + i
            path = "m/44'/4218'/{account}'/0'/0'".format(account=account_index)
            bip32_ctx = Bip32Slip10Ed25519.FromSeed(seed).DerivePath(path)
            # 获取32字节Ed25519公钥（与 test_iota_address.py 保持一致）
            pub = bip32_ctx.PublicKey()
            raw_bytes = pub.RawCompressed().ToBytes()
            # 如果长度>32，取最后32字节
            if len(raw_bytes) > 32:
                raw_bytes = raw_bytes[-32:]
            if len(raw_bytes) != 32:
                raise ValueError(f"期望 32 字节 Ed25519 公钥，但得到 {len(raw_bytes)} 字节")
            # 使用BLAKE2b-256哈希生成地址（与 test_iota_address.py 保持一致）
            h = blake2b(digest_size=32)
            h.update(raw_bytes)
            hashed = h.digest()
            # 返回带0x前缀的十六进制地址
            addr_list[i] = "0x" + hashed.hex()
        return addr_list


class count_ton_address:
    """
    TON地址计算
    注意：TON 使用自己的助记词格式，不是标准的 BIP39
    """

    def __init__(self, mnemonic, workchain=0, wallet_version=None, size=10):
        """
        @param mnemonic: TON 助记词（空格分隔的单词列表）
        @param workchain: 工作链ID，0=主网，-1=测试网
        @param wallet_version: 钱包版本，默认 v4r2
        @param size: 地址数量（TON 通常每个助记词对应一个地址，这里用于兼容接口）
        """
        if not TONSDK_AVAILABLE:
            raise RuntimeError("未安装 tonsdk 库，请先安装: pip install tonsdk")
        if wallet_version is None:
            wallet_version = WalletVersionEnum.v4r2
        self.mnemonic = ' '.join(mnemonic.split())
        self.workchain = workchain
        self.wallet_version = wallet_version
        self.size = size
        self.ton_address = self._from_mnemonic_ton_address()

    def _from_mnemonic_ton_address(self):
        """
        从 TON 助记词生成地址
        """
        # TON 助记词是空格分隔的单词列表
        mn_words = self.mnemonic.split()
        
        # 使用 tonsdk 生成钱包
        _mn, pub_k, _priv_k, wallet = Wallets.from_mnemonics(
            mn_words, 
            self.wallet_version, 
            self.workchain
        )
        
        # 存储公钥（十六进制）
        self.public_key = binascii.hexlify(pub_k).decode()
        
        # 存储地址（原始格式和可弹跳主网格式）
        self.address_raw = wallet.address.to_string()
        self.address_bounceable = wallet.address.to_string(True, True, False)
        
        # 返回地址列表（为了兼容其他链的接口，返回相同地址）
        addr_list = [self.address_bounceable for _ in range(self.size)]
        return addr_list


class count_bip39_ton_address:
    """
    TON地址计算（使用 BIP39 助记词）
    通过调用 Node.js 脚本 ton_from_mnemonic.js 来计算地址
    """

    def __init__(self, mnemonic, passphrase='', workchain=0, wallet_version=None, size=10):
        """
        @param mnemonic: BIP39 助记词
        @param passphrase: BIP39 密码短语
        @param workchain: 工作链ID，0=主网，-1=测试网（目前未使用，Node.js 脚本固定为 0）
        @param wallet_version: 钱包版本，默认 v4r2（目前未使用，Node.js 脚本固定为 v4r2）
        @param size: 地址数量（目前未使用，只生成一个地址）
        """
        # 这个类不直接使用 tonsdk，所以不需要检查
        # wallet_version 参数保留用于兼容性，但实际上不使用
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.workchain = workchain
        self.wallet_version = wallet_version
        self.size = size
        self.address = self._from_mnemonic_ton_address()

    def _from_mnemonic_ton_address(self):
        """
        从 BIP39 助记词生成 TON 地址
        通过调用 Node.js 脚本 ton_from_mnemonic.js
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
        js_script_candidates = [
            os.path.join(project_root, "node", "ton", "ton_from_mnemonic.js"),
            os.path.join(script_dir, "ton_from_mnemonic.js"),
        ]
        js_script_path = next((path for path in js_script_candidates if os.path.exists(path)), None)
        if js_script_path is None:
            raise FileNotFoundError(f"ton_from_mnemonic.js not found. Searched: {js_script_candidates}")
        
        # 调用 Node.js 脚本，传递助记词和 passphrase 作为参数
        result = subprocess.run(
            ["node", js_script_path, self.mnemonic, self.passphrase],
            capture_output=True,
            text=True,
            check=True
        )
        # 获取输出的地址（去除换行符）
        address = result.stdout.strip()
        return address


def get_rsa_primes_from_rust(seed: bytes, verbose: bool = False) -> Tuple[int, int]:
    """
    调用 Rust 的 rsa 和 rand_chacha 包生成 RSA 素数
    这是唯一调用 Rust 的地方，其他所有逻辑都在 Python 中
    
    Args:
        seed: BIP39 seed (64 bytes)，Rust 函数内部会处理双重 SHA-256
        verbose: 是否输出详细信息
    
    Returns:
        (p, q): 两个 2048 位的素数
    """
    # 定义 RsaResult 结构（对应 Rust 的 RsaResult）
    class RsaResult(Structure):
        _fields_ = [
            ("error_code", c_uint),
            ("error_message", c_char_p),
            ("p_bytes", POINTER(c_uint8)),
            ("q_bytes", POINTER(c_uint8)),
            ("p_len", c_size_t),
            ("q_len", c_size_t),
        ]
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
    rust_crate_dir = os.path.join(project_root, "crates", "rust_rsa_ffi")
    lib_name = f"librust_rsa_ffi{'.so' if sys.platform != 'darwin' else '.dylib'}"
    lib_paths = [
        os.path.join(rust_crate_dir, "target", "release", lib_name),
        os.path.join(rust_crate_dir, "target", "debug", lib_name),
        os.path.join(script_dir, "rust_rsa_ffi", "target", "release", lib_name),
        os.path.join(script_dir, "rust_rsa_ffi", "target", "debug", lib_name),
        lib_name,
    ]
    
    lib_path = None
    for path in lib_paths:
        if os.path.exists(path):
            lib_path = path
            break
    
    if lib_path is None:
        raise RuntimeError(
            f"Rust library not found. Please build it first:\n"
            f"  cd crates/rust_rsa_ffi && cargo build --release\n"
            f"Searched paths: {lib_paths}"
        )
    
    # 加载动态库
    lib = ctypes.CDLL(lib_path)
    
    # 定义函数签名
    lib.generate_rsa_primes_from_seed.argtypes = [POINTER(c_uint8), c_size_t]
    lib.generate_rsa_primes_from_seed.restype = RsaResult
    
    lib.free_rsa_result.argtypes = [POINTER(RsaResult)]
    lib.free_rsa_result.restype = None
    
    # 准备输入
    seed_array = (c_uint8 * len(seed))(*seed)
    seed_len = c_size_t(len(seed))
    
    # 调用 Rust 函数
    result = lib.generate_rsa_primes_from_seed(seed_array, seed_len)
    
    # 检查错误
    if result.error_code != 0:
        error_msg = result.error_message.decode("utf-8") if result.error_message else "Unknown error"
        raise RuntimeError(f"Rust function returned error {result.error_code}: {error_msg}")
    
    # 读取结果
    if result.p_bytes is None or result.q_bytes is None:
        raise RuntimeError("Rust function returned null data")
    
    if result.p_len == 0 or result.q_len == 0:
        raise RuntimeError("Rust function returned zero-length primes")
    
    # 复制数据（在释放内存之前）
    p_bytes = bytes(ctypes.string_at(result.p_bytes, result.p_len))
    q_bytes = bytes(ctypes.string_at(result.q_bytes, result.q_len))
    
    # 转换为整数
    p = int.from_bytes(p_bytes, "big")
    q = int.from_bytes(q_bytes, "big")
    
    # 释放 Rust 分配的内存
    lib.free_rsa_result(ctypes.byref(result))
    
    return p, q


def int_to_be_bytes(value: int) -> bytes:
    """
    将整数转换为大端字节序
    """
    if value == 0:
        return b"\x00"
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, "big")


class count_arweave_address:
    """
    Arweave 地址计算
    与 Keystone 硬件钱包逻辑保持一致
    """

    def __init__(self, mnemonic, passphrase, size=1):
        """
        @param mnemonic: BIP39 助记词
        @param passphrase: BIP39 passphrase
        @param size: 地址数量（默认1个）
        """
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.size = size
        self.seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        # 保存每个地址对应的 RSA 素数 (p, q)
        self.rsa_primes = []
        self.arweave_address = self._from_mnemonic_arweave_address()

    def _from_mnemonic_arweave_address(self):
        """
        从 BIP39 助记词生成 Arweave 地址
        流程：
        1. get_rsa_primes_from_rust(bip39_seed) -> p, q (Rust: 内部处理双重 SHA-256 + rsa + rand_chacha)
        2. generate_rsa_public_key(p, q) -> n (Python)
        3. int_to_be_bytes(n) -> n_bytes (Python)
        4. generate_address(n_bytes) -> address (Python)
        """
        addr_list = []
        for i in range(self.size):
            # Step 1: 生成 RSA 素数（调用 Rust 的 rsa + rand_chacha 包）
            # Rust 函数内部会处理双重 SHA-256
            p, q = get_rsa_primes_from_rust(self.seed, verbose=False)
            self.rsa_primes.append((p, q))
            
            # Step 2: 计算 modulus n = p * q（Python）
            n = p * q
            
            # Step 3: 转换为字节（Python）
            n_bytes = int_to_be_bytes(n)
            
            # Step 4: 生成地址（Python）
            # SHA-256
            hasher = hashlib.sha256()
            hasher.update(n_bytes)
            hash_bytes = hasher.digest()
            
            # Base64URL 编码（无填充）
            address = base64.urlsafe_b64encode(hash_bytes).decode("ascii").rstrip("=")
            addr_list.append(address)
        
        return addr_list


class count_monero_address:
    """
    Monero 地址计算（Keystone 硬件钱包方法）
    - 使用 BIP39 seed 作为输入，按照 Keystone 硬件钱包的逻辑生成地址
    - 使用 BIP44 路径 m/44'/128'/{account}'/0/0（128 是 Monero 的 coin type）
    - 需要可选依赖 monero (monero-python) 和 pysha3。未安装将抛出友好错误
    - 仅输出主地址（不生成子地址）
    """
    # Ed25519 曲线阶 L = 2^252 + 27742317777372353535851937790883648493
    CURVE_L = int("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

    def __init__(self, mnemonic, passphrase, size=1):
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.size = size
        if not NACL_AVAILABLE:
            raise RuntimeError("未安装 PyNaCl 库，请先安装: pip install pynacl")
        self.seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)  # 64-byte BIP39 seed
        self.addresses = self._from_seed_keystone_address()

    @staticmethod
    def _keccak256(data: bytes) -> bytes:
        """
        Keccak-256 哈希（不是 SHA3-256）
        优先使用 pysha3 的 keccak；无则回退到 Crypto.Hash.keccak
        """
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()

    @classmethod
    def _sc_reduce32_le(cls, data: bytes) -> bytes:
        """
        标量约简：将 32 字节数据约简到 Ed25519 曲线阶 L
        Monero 标准：将输入按 little-endian 解释取模，结果以 little-endian 返回
        """
        # 确保输入是 32 字节
        if len(data) > 32:
            data = data[:32]
        elif len(data) < 32:
            data = data + b'\x00' * (32 - len(data))

        # 将数据解释为 little-endian 整数（Monero 标准）
        n = int.from_bytes(data, "little")
        # 模 L（Ed25519 曲线阶）
        r = n % cls.CURVE_L
        # 返回 32 字节 little-endian
        return r.to_bytes(32, "little")

    def _hash_to_scalar(self, data: bytes) -> bytes:
        """
        hash_to_scalar: Keccak-256 哈希后标量约简
        这是 Monero 标准的密钥派生方法
        """
        # 直接对输入进行 Keccak-256 哈希（不反转）
        h = self._keccak256(data)
        return self._sc_reduce32_le(h)

    def _derive_entropy_from_bip44_path(self, seed: bytes, account: int = 0) -> bytes:
        """
        使用 BIP44 路径派生 secp256k1 私钥（作为 entropy）
        路径: m/44'/128'/{account}'/0/0
        128 是 Monero 的 coin type
        使用标准 BIP32 (secp256k1) 实现，与 Rust bitcoin::bip32 对齐
        """
        path = f"m/44'/128'/{account}'/0/0"
        # 使用纯 Python BIP32 实现（标准 BIP32，不是 SLIP-0010）
        return self._bip32_k1_derive_priv_be(seed, path)

    def _ed25519_public_from_scalar_le(self, scalar_le: bytes) -> bytes:
        """
        从 32 字节 little-endian scalar 计算 Ed25519 公钥
        匹配 Rust 实现：PublicKey::from 会再次调用 Scalar::from_bytes_mod_order
        使用 nacl.bindings.crypto_scalarmult_ed25519_base_noclamp（不进行 clamping，符合 Monero 规范）
        """
        if len(scalar_le) != 32:
            raise ValueError("scalar must be 32 bytes")
        # 匹配 Rust: Scalar::from_bytes_mod_order(private_key.to_bytes())
        # Rust 代码中，PrivateKey::to_bytes() 返回 scalar.to_bytes() (little-endian)
        # 然后 Scalar::from_bytes_mod_order 再次进行标量约简
        # 所以我们需要再次进行 from_bytes_mod_order
        scalar_reduced = self._sc_reduce32_le(scalar_le)
        return crypto_scalarmult_ed25519_base_noclamp(scalar_reduced)

    def _monero_base58_encode(self, data: bytes) -> str:
        """
        Monero Base58 编码（8 字节块，参考官方实现的逐字节除法法）
        - 8 字节块编码为 11 个字符
        - 最后 5 字节块编码为 7 个字符
        采用基于 base256 -> base58 的逐字节除法（高位在前），与 Monero C++ 实现一致，
        可确保主网地址以 '4' 开头。
        """
        ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        res = ""
        i = 0
        # 69 字节数据分块：8 字节 -> 11 字符；最后 5 字节 -> 7 字符
        while i < len(data):
            block = data[i:i+8]
            block_len = len(block)
            size = 11 if block_len == 8 else 7
            # 基于数组的除法算法（处理为大端 base256）
            digits = ["1"] * size
            # 使用可变数组进行就地除法
            nums = list(block)
            for pos in range(size - 1, -1, -1):
                remainder = 0
                for j in range(block_len):
                    c = remainder * 256 + nums[j]
                    nums[j] = c // 58
                    remainder = c % 58
                digits[pos] = ALPHABET[remainder]
            res += "".join(digits)
            i += 8
        return res

    @staticmethod
    def _hmac_sha512(key: bytes, data: bytes) -> bytes:
        import hmac, hashlib
        return hmac.new(key, data, hashlib.sha512).digest()

    def _bip32_k1_derive_priv_be(self, seed: bytes, path: str) -> bytes:
        """
        使用 BIP32 (secp256k1) 从 seed 按路径派生私钥（32-byte big-endian）
        路径示例: m/44'/128'/{account}'/0/0
        """
        # 严格的纯 Python BIP32 CKDpriv 实现（避免外部依赖/Node）
        from ecdsa import SECP256k1, SigningKey
        n = SECP256k1.order

        def ser32(i: int) -> bytes:
            return i.to_bytes(4, "big")

        def point_compressed_from_priv(priv_be: bytes) -> bytes:
            sk = SigningKey.from_string(priv_be, curve=SECP256k1)
            vk = sk.get_verifying_key()
            x = vk.pubkey.point.x()
            y = vk.pubkey.point.y()
            prefix = 0x02 if (y % 2 == 0) else 0x03
            return bytes([prefix]) + x.to_bytes(32, "big")

        # master key
        I = self._hmac_sha512(b"Bitcoin seed", seed)
        k_par = I[:32]
        c_par = I[32:]
        k_par_int = int.from_bytes(k_par, "big")
        if k_par_int == 0 or k_par_int >= n:
            raise ValueError("Invalid master key (zero or >= n)")

        # parse path
        elems = path.split("/")
        if elems[0] != "m":
            raise ValueError("path must start with m")
        indexes = []
        for e in elems[1:]:
            if e.endswith("'"):
                indexes.append(int(e[:-1]) + 0x80000000)
            else:
                indexes.append(int(e))

        # iterate CKDpriv
        for idx in indexes:
            hardened = (idx & 0x80000000) != 0
            if hardened:
                data = b"\x00" + k_par + ser32(idx)
            else:
                pubc = point_compressed_from_priv(k_par)
                data = pubc + ser32(idx)
            I = self._hmac_sha512(c_par, data)
            Il, Ir = I[:32], I[32:]
            il_int = int.from_bytes(Il, "big")
            if il_int == 0 or il_int >= n:
                raise ValueError("Invalid child derivation (Il out of range)")
            child_int = (il_int + int.from_bytes(k_par, "big")) % n
            if child_int == 0:
                raise ValueError("Invalid child derivation (key = 0)")
            k_par = child_int.to_bytes(32, "big")
            c_par = Ir

        return k_par

    def _monero_address_from_pubkeys(self, pub_spend: bytes, pub_view: bytes, network_prefix: bytes = b'\x12', is_subaddress: bool = False) -> str:
        """
        从公钥构建 Monero 地址
        network_prefix: b'\x12' 为主网标准地址，b'\x2A' 为主网子地址
        is_subaddress: 是否为子地址
        """
        if is_subaddress:
            network_prefix = b'\x2A'  # 主网子地址前缀
        data = network_prefix + pub_spend + pub_view
        checksum = self._keccak256(data)[:4]
        addr = self._monero_base58_encode(data + checksum)
        return addr

    def _calc_subaddress_m(self, secret_view_key: bytes, major: int, minor: int) -> bytes:
        """
        计算子地址的 m 值 (h)
        根据 Rust 代码 calc_subaddress_m:
        h = hs("SubAddr\0" | secret_view_key | major | minor)
        - prefix: "SubAddr" (注意：大写 A)
        - secret_view_key: 32 bytes
        - major: 4 bytes, little-endian
        - minor: 4 bytes, little-endian
        """
        prefix = b"SubAddr"  # 注意：大写 'A'，根据 Rust 代码
        data = prefix + b'\x00' + secret_view_key + major.to_bytes(4, "little") + minor.to_bytes(4, "little")
        return self._hash_to_scalar(data)

    def _from_seed_keystone_address(self):
        """
        Keystone 硬件钱包的 Monero 地址生成流程：
        
        重要：根据 Rust 测试代码，所有子地址都使用 major=0 的 keypair（路径 m/44'/128'/0'/0/0），
        但 major 和 minor 参数来自路径的 x 和 i。
        
        对于路径 m/44'/128'/{x}'/0/{i}：
        - 总是使用 x=0 的 keypair（路径 m/44'/128'/0'/0/0）
        - 如果 x=0, i=0：主地址（is_subaddress=false, major=0, minor=0）
        - 如果 x=0, i>0：子地址（is_subaddress=true, major=0, minor=i）
        - 如果 x>0, i=0：子地址（is_subaddress=true, major=x, minor=0）- 使用 x=0 的 keypair
        - 如果 x>0, i>0：子地址（is_subaddress=true, major=x, minor=i）- 使用 x=0 的 keypair
        
        子地址生成步骤（根据文档和 Rust 测试）：
        1. 计算 h = hs("SubAddr\0" | secret_view_key | major | minor)
           - secret_view_key: 来自 x=0 的 keypair
           - major: x (路径中的 account index)
           - minor: i (路径中的 address index)
        2. 子psk = 父pvk + G(h)
           - 父pvk: pub_spend_main_0 (x=0 的公钥 spend key)
           - G(h): h * G (Ed25519 base point)
           - 子psk: pub_spend (子公钥 spend key)
        3. 子pvk = 父svk * 子psk
           - 父svk: secret_view_key_0 (x=0 的私钥 view key)
           - 子psk: pub_spend (子公钥 spend key)
           - 子pvk: pub_view (子公钥 view key)
        
        生成路径 m/44'/128'/{x}'/0/{i} 的地址，其中 x 和 i 都从 0 到 5
        """
        from nacl.bindings import crypto_core_ed25519_add, crypto_scalarmult_ed25519_noclamp
        
        addresses = []
        
        # 预先计算 x=0 的 keypair（所有子地址都使用这个）
        path_0 = "m/44'/128'/0'/0/0"
        entropy_0 = self._bip32_k1_derive_priv_be(self.seed, path_0)
        secret_spend_key_0 = self._hash_to_scalar(entropy_0)
        secret_view_key_0 = self._hash_to_scalar(secret_spend_key_0)
        pub_spend_main_0 = self._ed25519_public_from_scalar_le(secret_spend_key_0)
        pub_view_main_0 = self._ed25519_public_from_scalar_le(secret_view_key_0)
        
        # x 和 i 都从 0 到 5
        for x in range(6):
            for i in range(6):
                path = f"m/44'/128'/{x}'/0/{i}"
                
                # 只有 x=0 且 i=0 是主地址，其他都是子地址
                if x == 0 and i == 0:
                    # 主地址：直接使用 x=0 的主公钥
                    pub_spend = pub_spend_main_0
                    pub_view = pub_view_main_0
                    is_subaddress = False
                else:
                    # 所有子地址都使用 x=0 的 keypair
                    # 确定 major 和 minor：major=x, minor=i
                    major = x
                    minor = i
                    
                    # 子地址生成：
                    # 1. 计算 h = hs("Subaddr\0" | a | account index | address index)
                    h_scalar = self._calc_subaddress_m(secret_view_key_0, major, minor)
                    
                    # 2. 子psk = 父pvk + G(h)
                    # G(h) = h * G (Ed25519 base point)
                    G_h = crypto_scalarmult_ed25519_base_noclamp(h_scalar)
                    # 子psk = 父pvk + G(h)
                    pub_spend = crypto_core_ed25519_add(pub_spend_main_0, G_h)
                    
                    # 3. 子pvk = 父svk * 子psk
                    # 父svk 是 secret_view_key_0 (标量)
                    # 子psk 是 pub_spend (点)
                    # 子pvk = 父svk * 子psk
                    pub_view = crypto_scalarmult_ed25519_noclamp(secret_view_key_0, pub_spend)
                    is_subaddress = True
                
                # 步骤 5: 从公钥构建 Monero 地址
                address = self._monero_address_from_pubkeys(pub_spend, pub_view, network_prefix=b'\x12', is_subaddress=is_subaddress)
                addresses.append({
                    'path': path,
                    'address': address,
                    'x': x,
                    'i': i
                })
        
        return addresses

class count_cosmos_address:

    def __init__(self, mnemonic, passphrase, change,external, address_index):
        DEFAULT_DERIVATION_PATH = "m/44'/118'/{change}'/{external}/{address_index}".format(change=change,external=external,address_index=address_index)
        SCRT_DERIVATION_PATH = "m/44'/529'/{change}'/{external}/{address_index}".format(change=change,external=external,address_index=address_index)
        CRO_DERIVATION_PATH = "m/44'/394'/{change}'/{external}/{address_index}".format(change=change,external=external,address_index=address_index)
        IOV_DERIVATION_PATH = "m/44'/234'/{change}'/{external}/{address_index}".format(change=change,external=external,address_index=address_index)
        BLD_DERIVATION_PATH = "m/44'/564'/{change}'/{external}/{address_index}".format(change=change,external=external,address_index=address_index)
        ETH_DERIVATION_PATH = "m/44'/60'/{change}'/{external}/{address_index}".format(change=change,external=external,address_index=address_index)
        KAVA_DERIVATION_PATH = "m/44'/459'/{change}'/{external}/{address_index}".format(change=change,external=external,address_index=address_index)
        TERRA_DERIVATION_PATH = "m/44'/330'/{change}'/{external}/{address_index}".format(change=change,external=external,address_index=address_index)
        RUNE_DERIVATION_PATH = "m/44'/931'/{change}'/{external}/{address_index}".format(change=change,external=external,address_index=address_index)

        BABY_BECH32_HRP='bbn'
        NTMPI__BECH32_HRP='neutaro'
        TIA_BECH32_HRP = "celestia"
        NTRN_BECH32_HRP = 'neutron'
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

        if not COSMOSPY_AVAILABLE:
            raise RuntimeError("未安装 cosmospy 库，请先安装: pip install cosmospy")

        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.cosmos_privkey = seed_to_privkey_with_passphrase(self.mnemonic, path=DEFAULT_DERIVATION_PATH, passphrase=self.passphrase)
        self.cosmos_pubkey = privkey_to_pubkey(self.cosmos_privkey)
        # ETH 路径派生，需要支持 passphrase
        self.eth_privkey = seed_to_privkey_with_passphrase(self.mnemonic, path=ETH_DERIVATION_PATH, passphrase=self.passphrase)
        self.eth_pubkey = privkey_to_pubkey(self.eth_privkey)
        # INJ/DYM/EVMOS 使用 ETH 派生路径 m/44'/60'/0'/0/0（EVM 风格地址）
        # 不强依赖 pyinjective：直接从未压缩公钥计算 20-byte 地址再做 bech32 编码
        from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
        from eth_hash.auto import keccak
        seed_with_passphrase = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        bip44_ctx = Bip44.FromSeed(seed_with_passphrase, Bip44Coins.ETHEREUM)
        eth_account = bip44_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        eth_pub_uncompressed = eth_account.PublicKey().RawUncompressed().ToBytes()[1:]  # 去掉 0x04 前缀
        evm_addr_bytes = keccak(eth_pub_uncompressed)[-20:]
        self.cro_privkey = seed_to_privkey_with_passphrase(self.mnemonic, path=CRO_DERIVATION_PATH, passphrase=self.passphrase)
        self.cro_pubkey = privkey_to_pubkey(self.cro_privkey)
        self.kava_privkey = seed_to_privkey_with_passphrase(self.mnemonic, path=KAVA_DERIVATION_PATH, passphrase=self.passphrase)
        self.kava_pubkey = privkey_to_pubkey(self.kava_privkey)
        self.lunc_privkey = seed_to_privkey_with_passphrase(self.mnemonic, path=TERRA_DERIVATION_PATH, passphrase=self.passphrase)
        self.lunc_pubkey = privkey_to_pubkey(self.lunc_privkey)
        self.scrt_privkey = seed_to_privkey_with_passphrase(self.mnemonic, path=SCRT_DERIVATION_PATH, passphrase=self.passphrase)
        self.scrt_pubkey = privkey_to_pubkey(self.scrt_privkey)
        self.iov_privkey = seed_to_privkey_with_passphrase(self.mnemonic, path=IOV_DERIVATION_PATH, passphrase=self.passphrase)
        self.iov_pubkey = privkey_to_pubkey(self.iov_privkey)
        self.bld_privkey = seed_to_privkey_with_passphrase(self.mnemonic, path=BLD_DERIVATION_PATH, passphrase=self.passphrase)
        self.bld_pubkey = privkey_to_pubkey(self.bld_privkey)
        self.rune_privkey = seed_to_privkey_with_passphrase(self.mnemonic, path=RUNE_DERIVATION_PATH, passphrase=self.passphrase)
        self.rune_pubkey = privkey_to_pubkey(self.rune_privkey)

        self.baby_address = pubkey_to_address(self.cosmos_pubkey, hrp=BABY_BECH32_HRP)
        self.neutaro_address = pubkey_to_address(self.cosmos_pubkey, hrp=NTMPI__BECH32_HRP)
        self.tia_address = pubkey_to_address(self.cosmos_pubkey, hrp=TIA_BECH32_HRP)
        self.ntur_address = pubkey_to_address(self.cosmos_pubkey, hrp=NTRN_BECH32_HRP)
        # DYM/INJ/EVMOS 使用同一组 20-byte 地址数据，仅 HRP 不同
        import bech32
        evm_5bit_data = bech32.convertbits(evm_addr_bytes, 8, 5, True)
        self.dym_address = bech32.bech32_encode(DYM_BECH32_HRP, evm_5bit_data)
        self.osmo_address = pubkey_to_address(self.cosmos_pubkey, hrp=OSMO_BECH32_HRP)
        self.inj_address = bech32.bech32_encode("inj", evm_5bit_data)
        self.atom_address = pubkey_to_address(self.cosmos_pubkey, hrp=ATOM_BECH32_HRP)
        self.cro_address = pubkey_to_address(self.cro_pubkey, hrp=CRO_BECH32_HRP)
        self.rune_address = pubkey_to_address(self.rune_pubkey, hrp=RUNE_BECH32_HRP)
        self.kava_address = pubkey_to_address(self.kava_pubkey, hrp=KAVA_BECH32_HRP)
        self.lunc_address = pubkey_to_address(self.lunc_pubkey, hrp=LUNC_BECH32_HRP)
        self.axl_address = pubkey_to_address(self.cosmos_pubkey, hrp=AXL_BECH32_HRP)
        self.luna_address = pubkey_to_address(self.lunc_pubkey, hrp=LUNA_BECH32_HRP)
        self.akt_address = pubkey_to_address(self.cosmos_pubkey, hrp=AKT_BECH32_HRP)
        self.strd_address = pubkey_to_address(self.cosmos_pubkey, hrp=STRD_BECH32_HRP)
        self.scrt_address = pubkey_to_address(self.scrt_pubkey, hrp=SCRT_BECH32_HRP)
        self.bld_address = pubkey_to_address(self.bld_pubkey, hrp=BLD_BECH32_HRP)
        self.ctk_address = pubkey_to_address(self.cosmos_pubkey, hrp=CTK_BECH32_HRP)
        # EVMOS 使用相同 20-byte 地址数据
        self.evmos_address = bech32.bech32_encode(EVMOS_BECH32_HRP, evm_5bit_data)
        self.stars_address = pubkey_to_address(self.cosmos_pubkey, hrp=STARS_BECH32_HRP)
        self.xprt_address = pubkey_to_address(self.cosmos_pubkey, hrp=XPRT_BECH32_HRP)
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


class count_zec_address:
    """
    ZEC 地址计算（Keystone 工作流）
    - Seed Fingerprint: BLAKE2b(seed)（类似 MFP）
    - Key Generation: ZIP32 USK 路径 32'/133'/{account}'
      - USK 内含 Transparent K1 扩展私钥 与 Orchard Spending Key
      - 由 USK 生成 UFVK（Unified Full Viewing Key）
    - Address: 由 UFVK 生成 Unified Address（取第 0 个组件集：含透明 + orchard）
    说明：本实现使用延迟导入，若缺少相关依赖，将优雅回退并提示安装步骤。
    """

    def __init__(self, mnemonic: str, passphrase: str = "", account: int = 0):
        self.mnemonic = ' '.join(mnemonic.split())
        self.passphrase = passphrase
        self.account = account
        # BIP39 seed
        self.seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
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

    test_mnemonic = os.environ.get("BIP39_MNEMONIC")
    ton_mnemonic = os.environ.get("TON_MNEMONIC")
    test_passphrase = os.environ.get("BIP39_PASSPHRASE", "")
    if not test_mnemonic or not ton_mnemonic:
        raise SystemExit("Set BIP39_MNEMONIC and TON_MNEMONIC before running this script.")
    btc_address = count_btc_address(test_mnemonic, test_passphrase)
    print("---------------BTC地址---------------")
    for index in range(min(10, btc_address.size)):
        print("Address-%d" % index, btc_address.bip84_address[index], "    ", btc_address.bip86_address[index], "    ",
              btc_address.bip49_address[index], "    ", btc_address.bip44_address[index])
    print("---------------BTC xpub---------------")
    print(btc_address.bip84_zpublic_key, '    ', btc_address.bip86_xpublic_key, '    ', btc_address.bip49_ypublic_key,
          '    ', btc_address.bip44_xpublic_key)
    btc_test_address = count_btc_address(test_mnemonic, test_passphrase, testnet=True)
    print("---------------BTC TEST地址---------------")
    print("%-9s %-44s %-62s %-36s %s" % ("", "BIP84(Native SegWit)", "BIP86(Taproot)", "BIP49(Nested SegWit)", "BIP44(Legacy)"))
    for index in range(min(10, btc_test_address.size)):
        print("Address-%d" % index, btc_test_address.bip84_address[index], "    ", btc_test_address.bip86_address[index], "    ",
              btc_test_address.bip49_address[index], "    ", btc_test_address.bip44_address[index])
    print("---------------BTC TEST xpub---------------")
    print(btc_test_address.bip84_zpublic_key, '    ', btc_test_address.bip86_xpublic_key, '    ', btc_test_address.bip49_ypublic_key,
          '    ', btc_test_address.bip44_xpublic_key)
    eth_address = count_eth_address(test_mnemonic, test_passphrase)
    print("---------------ETH地址---------------")
    for index in range(min(10, eth_address.size)):
        print("Account-%d" % (index + 1), eth_address.bip44_address[index], "    ",
              eth_address.ledger_live_address[index], "    ", eth_address.ledger_legacy_address[index])
    sol_address = count_solana_address(test_mnemonic, test_passphrase)
    print("---------------SOL地址---------------")
    for index in range(min(10, sol_address.size)):
        print("Account-%d" % (index + 1), sol_address.account_based_path_address[index], "      ",
              sol_address.sub_account_path_address[index], "      ",
              sol_address.single_account_path_address)
    # SOL public key for specific paths
    print("---------------SOL PublicKey---------------")
    sol_seed = Bip39SeedGenerator(test_mnemonic).Generate(test_passphrase)
    sol_pubkey_account = SoldersKeypair.from_seed_and_derivation_path(sol_seed, "m/44'/501'/0'").pubkey()
    sol_pubkey_sub = SoldersKeypair.from_seed_and_derivation_path(sol_seed, "m/44'/501'/0'/0'").pubkey()
    print(f"m/44'/501'/0'    pubkey(hex): {bytes(sol_pubkey_account).hex()}")
    print(f"m/44'/501'/0'/0' pubkey(hex): {bytes(sol_pubkey_sub).hex()}")
    xrp_address = count_xrp_address(test_mnemonic, test_passphrase)
    print("---------------XRP地址---------------")
    for index in range(min(10, xrp_address.size)):
        print("Account-%d" % (index + 1), xrp_address.bip44_address[index])
    # ADA 地址
    ada_address = count_ada_address(test_mnemonic, test_passphrase)
    print("---------------ADA地址---------------")
    # 按 i 分组显示，每个 i 显示 5 个地址（x 从 0 到 4）
    for i in range(6):
        print(f"\nm/1852'/1815'/{i}'/0/ 下的地址:")
        print("-" * 80)
        for x in range(5):
            addr_info = next((a for a in ada_address.addresses if a['i'] == i and a['x'] == x), None)
            if addr_info:
                print(f"  [{x}] {addr_info['path']}")
                print(f"      {addr_info['address']}")
    print("\n---------------ADA地址(Ledger/BitBox02)---------------")
    # 按 i 分组显示，每个 i 显示 5 个地址（x 从 0 到 4）
    for i in range(6):
        print(f"\nm/1852'/1815'/{i}'/0/ 下的地址:")
        print("-" * 80)
        for x in range(5):
            addr_info = next((a for a in ada_address.ledger_bitbox02_addresses if a['i'] == i and a['x'] == x), None)
            if addr_info:
                print(f"  [{x}] {addr_info['path']}")
                print(f"      {addr_info['address']}")
    print("\n---------------ADA地址(Enterprise)---------------")
    for i in range(6):
        print(f"\nm/1852'/1815'/{i}'/0/ 下的 Enterprise 地址:")
        print("-" * 80)
        for x in range(5):
            addr_info = next((a for a in ada_address.enterprise_addresses if a['i'] == i and a['x'] == x), None)
            if addr_info:
                print(f"  [{x}] {addr_info['path']}")
                print(f"      {addr_info['address']}")
    # TON 地址（使用 TON 专用助记词，不是 BIP39）
    ton_address = count_ton_address(ton_mnemonic)
    print("---------------TON地址---------------")
    print("公钥:", ton_address.public_key)
    print("地址:", ton_address.address_bounceable)
    # TON 地址（使用 BIP39 助记词）
    bip39_ton_address = count_bip39_ton_address(test_mnemonic, test_passphrase)
    print("---------------TON地址(BIP39)---------------")
    print("地址:", bip39_ton_address.address)
    # ZEC 地址（Keystone 工作流）
    try:
        zec = count_zec_address(test_mnemonic, test_passphrase, account=0)
        print("---------------ZEC---------------")
        print("t-addr:", zec.transparent_address)
        print("u-addr:", zec.unified_address)
    except Exception as e:
        print("ZEC 生成失败:", e)
    trx_address = count_tron_address(test_mnemonic, test_passphrase)
    print("---------------TRX地址---------------")
    for index in range(min(10, trx_address.size)):
        print("Account-%d" % (index + 1), trx_address.bip44_address[index])
    ltc_address = count_ltc_address(test_mnemonic, test_passphrase)
    print("---------------LTC地址 (BIP44 Legacy P2PKH)---------------")
    for index in range(min(10, ltc_address.size)):
        print("Account-%d" % (index + 1), ltc_address.bip44_address[index])
    print("---------------LTC地址 (BIP49 P2SH-SegWit)---------------")
    for index in range(min(10, ltc_address.size)):
        print("Account-%d" % (index + 1), ltc_address.bip49_address[index])
    print("---------------LTC地址 (BIP84 Native SegWit - ltc1开头)---------------")
    for index in range(min(10, ltc_address.size)):
        print("Account-%d" % (index + 1), ltc_address.bip84_address[index])
    bch_address = count_bch_address(test_mnemonic, test_passphrase)
    print("---------------BCH地址---------------")
    for index in range(min(10, bch_address.size)):
        print("Account-%d" % (index + 1), bch_address.bip44_address[index])
    doge_address = count_doge_address(test_mnemonic, test_passphrase)
    print("---------------DOGE---------------")
    for index in range(min(10, doge_address.size)):
            print("Account-%d" % (index + 1), doge_address.bip44_address[index])
    # AVAX 地址
    avax_address = count_avax_address(test_mnemonic, test_passphrase)
    print("---------------AVAX地址---------------")
    for index in range(min(15, avax_address.size)):
        # 只输出 X 链地址（bech32 avax...）
        print("Account-%d" % (index + 1), avax_address.avax_address[index])
    # APT 地址
    apt_address = count_apt_address(test_mnemonic, test_passphrase)
    print("---------------APT地址---------------")
    for index in range(min(10, apt_address.size)):
        print("Account-%d" % (index + 1), apt_address.bip44_address[index])
    # SUI 地址
    sui_address = count_sui_address(test_mnemonic, test_passphrase)
    print("---------------SUI地址---------------")
    for index in range(min(10, sui_address.size)):
        print("Account-%d" % (index + 1), sui_address.sui_addr[index])
    iota_address = count_iota_address(test_mnemonic, test_passphrase)
    print("---------------IOTA地址---------------")
    for index in range(min(10, iota_address.size)):
        print("Account-%d" % (index + 1), iota_address.bip44_address[index])
    dash_address = count_dash_address(test_mnemonic,test_passphrase)
    print("---------------DASH---------------")
    for index in range(min(10, dash_address.size)):
        print("Account-%d" % (index + 1), dash_address.bip44_address[index])
    # Arweave 地址
    arweave_address = count_arweave_address(test_mnemonic, test_passphrase)
    print("---------------ARWEAVE地址---------------")
    print("Address-0", arweave_address.arweave_address[0])
    p, q = arweave_address.rsa_primes[0]
    print("p:", p)
    print("q:", q)
    # XLM 地址
    xml_address = count_xlm_address(test_mnemonic, test_passphrase)
    print("---------------XLM---------------")
    for index in range(min(10, xml_address.size)):
        print("Account-%d" % (index + 1), xml_address.bip44_address[index])
    # Cosmos 地址
    cosmos_address = count_cosmos_address(test_mnemonic,test_passphrase, change=0,external=0,address_index=0)
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
    print("---------------scrt--------------")
    print(cosmos_address.scrt_address)
    print("---------------bld--------------")
    print(cosmos_address.bld_address)
    print("---------------ctk--------------")
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
    monero_address = count_monero_address(test_mnemonic, test_passphrase, size=1)
    print("---------------XMR---------------")
    # 按 x 分组显示，每个 x 显示 5 个地址（i 从 0 到 4）
    for x in range(6):
        print(f"\nm/44'/128'/{x}'/0/ 下的地址:")
        print("-" * 80)
        for i in range(5):
            addr_info = next((a for a in monero_address.addresses if a['x'] == x and a['i'] == i), None)
            if addr_info:
                addr_type = "主地址" if x == 0 and i == 0 else "子地址"
                print(f"  [{i}] {addr_info['path']}")
                print(f"      {addr_info['address']} ({addr_type})")

