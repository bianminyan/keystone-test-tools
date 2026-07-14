"""CLI for deriving public chain addresses from BIP39 or SLIP39 inputs."""

from __future__ import annotations

import argparse
import os
import sys
from getpass import getpass
from pathlib import Path
from typing import Callable, Iterable, Sequence


if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _load_env_file(path: str | None) -> None:
    if not path:
        return
    env_path = Path(path).expanduser()
    if not env_path.exists():
        raise FileNotFoundError(f"env file not found: {env_path}")
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def _normalize_shares(value: str) -> str:
    return value.replace("\\n", "\n").strip()


def _print_section(title: str) -> None:
    print(f"\n---------------{title}---------------")


def _show(label: str, value: object) -> None:
    print(f"{label}: {value}")


def _show_list(label: str, values: Sequence[object], size: int) -> None:
    for index, value in enumerate(values[:size]):
        _show(f"{label}-{index}", value)


def _show_records(label: str, records: Sequence[dict], size: int) -> None:
    for index, record in enumerate(records[:size]):
        path = record.get("path")
        address = record.get("address")
        if path:
            _show(f"{label}-{index} {path}", address)
        else:
            _show(f"{label}-{index}", address)


def _try_chain(title: str, derive: Callable[[], None]) -> None:
    _print_section(title)
    try:
        derive()
    except Exception as exc:  # Keep one optional dependency from stopping all chains.
        print(f"FAILED: {exc}")


def _cosmos_names() -> Iterable[str]:
    return (
        "baby",
        "neutaro",
        "tia",
        "ntur",
        "dym",
        "osmo",
        "inj",
        "atom",
        "cro",
        "rune",
        "kava",
        "lunc",
        "axl",
        "luna",
        "akt",
        "strd",
        "scrt",
        "bld",
        "ctk",
        "evmos",
        "stars",
        "xprt",
        "somm",
        "juno",
        "iris",
        "dvpn",
        "rowan",
        "regen",
        "boot",
        "grav",
        "ixo",
        "ngm",
        "iov",
        "umee",
        "qck",
        "tgd",
    )


def derive_bip39(mnemonic: str, passphrase: str, size: int) -> None:
    from address_derivation.bip39_address import (
        count_ada_address,
        count_apt_address,
        count_arweave_address,
        count_avax_address,
        count_bch_address,
        count_bip39_ton_address,
        count_btc_address,
        count_cosmos_address,
        count_dash_address,
        count_doge_address,
        count_eth_address,
        count_iota_address,
        count_ltc_address,
        count_monero_address,
        count_solana_address,
        count_sui_address,
        count_tron_address,
        count_xlm_address,
        count_xrp_address,
        count_zec_address,
    )

    _try_chain("BTC", lambda: _print_bip39_btc(count_btc_address(mnemonic, passphrase, size=size), size))
    _try_chain("ETH", lambda: _print_bip39_eth(count_eth_address(mnemonic, passphrase, size=size), size))
    _try_chain("SOL", lambda: _print_sol(count_solana_address(mnemonic, passphrase, size=size), size))
    _try_chain("AVAX", lambda: _print_avax(count_avax_address(mnemonic, passphrase, size=size), size, "bip44_address"))
    _try_chain("TRON", lambda: _show_list("TRON", count_tron_address(mnemonic, passphrase, size=size).bip44_address, size))
    _try_chain("XRP", lambda: _show_list("XRP", count_xrp_address(mnemonic, passphrase, size=size).bip44_address, size))
    _try_chain("ADA", lambda: _print_bip39_ada(count_ada_address(mnemonic, passphrase, size=size), size))
    _try_chain("LTC", lambda: _print_bip39_ltc(count_ltc_address(mnemonic, passphrase, size=size), size))
    _try_chain("BCH", lambda: _show_list("BCH", count_bch_address(mnemonic, passphrase, size=size).bip44_address, size))
    _try_chain("APTOS", lambda: _show_list("APTOS", count_apt_address(mnemonic, passphrase, size=size).bip44_address, size))
    _try_chain("SUI", lambda: _show_list("SUI", count_sui_address(mnemonic, passphrase, size=size).sui_addr, size))
    _try_chain("DASH", lambda: _show_list("DASH", count_dash_address(mnemonic, passphrase, size=size).bip44_address, size))
    _try_chain("DOGE", lambda: _show_list("DOGE", count_doge_address(mnemonic, passphrase, size=size).bip44_address, size))
    _try_chain("XLM", lambda: _show_list("XLM", count_xlm_address(mnemonic, passphrase, size=size).bip44_address, size))
    _try_chain("IOTA", lambda: _show_list("IOTA", count_iota_address(mnemonic, passphrase, size=size).bip44_address, size))
    _try_chain("TON BIP39", lambda: _show("TON", count_bip39_ton_address(mnemonic, passphrase, size=size).address))
    _try_chain("ARWEAVE", lambda: _show_list("AR", count_arweave_address(mnemonic, passphrase, size=size).arweave_address, size))
    _try_chain("MONERO", lambda: _show_records("XMR", count_monero_address(mnemonic, passphrase, size=size).addresses, size))
    _try_chain("COSMOS STYLE", lambda: _print_bip39_cosmos(count_cosmos_address(mnemonic, passphrase, change=0, external=0, address_index=0)))
    _try_chain("ZEC", lambda: _print_zec(count_zec_address(mnemonic, passphrase, account=0)))


def _print_bip39_btc(value: object, size: int) -> None:
    _show_list("BTC BIP44 Legacy", value.bip44_address, size)
    _show_list("BTC BIP49 Nested SegWit", value.bip49_address, size)
    _show_list("BTC BIP84 Native SegWit", value.bip84_address, size)
    _show_list("BTC BIP86 Taproot", value.bip86_address, size)


def _print_bip39_eth(value: object, size: int) -> None:
    _show_list("ETH BIP44", value.bip44_address, size)
    _show_list("ETH Ledger Live", value.ledger_live_address, size)
    _show_list("ETH Ledger Legacy", value.ledger_legacy_address, size)


def _print_sol(value: object, size: int) -> None:
    _show_list("SOL account path", value.account_based_path_address, size)
    _show_list("SOL sub-account path", value.sub_account_path_address, size)
    _show("SOL single-account path", value.single_account_path_address)


def _print_avax(value: object, size: int, evm_attr: str) -> None:
    _show_list("AVAX BIP44", getattr(value, evm_attr), size)
    _show_list("AVAX X-Chain", value.avax_address, size)


def _print_bip39_ada(value: object, size: int) -> None:
    _show_records("ADA Shelley", value.addresses, size)
    _show_records("ADA Ledger/BitBox02", value.ledger_bitbox02_addresses, size)
    _show_records("ADA Enterprise", value.enterprise_addresses, size)


def _print_bip39_ltc(value: object, size: int) -> None:
    _show_list("LTC BIP44", value.bip44_address, size)
    _show_list("LTC BIP49", value.bip49_address, size)
    _show_list("LTC BIP84", value.bip84_address, size)


def _print_bip39_cosmos(value: object) -> None:
    for name in _cosmos_names():
        _show(name.upper(), getattr(value, f"{name}_address"))


def _print_zec(value: object) -> None:
    _show("ZEC transparent", value.transparent_address)
    if value.unified_address:
        _show("ZEC unified", value.unified_address)
    else:
        _show("ZEC unified", f"FAILED: {value.unified_address_error}")


def derive_slip39(shares: str, passphrase: str, size: int) -> None:
    from address_derivation.slip39_address import (
        count_ada_address,
        count_apt_address,
        count_avax_address,
        count_bch_address,
        count_btc_address,
        count_cosmos_address,
        count_dash_address,
        count_doge_address,
        count_eth_address,
        count_iota_address,
        count_ltc_address,
        count_slip39_arweave_address,
        count_slip39_ton_address,
        count_solana_address,
        count_sui_address,
        count_trx_address,
        count_xlm_address,
        count_xrp_address,
        count_zec_address,
        slip39_menmonic_to_byte_seed,
    )

    seed = slip39_menmonic_to_byte_seed(_normalize_shares(shares), passphrase=passphrase)
    _try_chain("BTC", lambda: _print_slip39_btc(count_btc_address(slip39_seed=seed, size=size), size))
    _try_chain("ETH", lambda: _print_slip39_eth(count_eth_address(slip39_seed=seed, size=size), size))
    _try_chain("SOL", lambda: _print_sol(count_solana_address(slip39_seed=seed, size=size), size))
    _try_chain("AVAX", lambda: _print_avax(count_avax_address(slip39_seed=seed, size=size), size, "seed_slip44_address"))
    _try_chain("TRON", lambda: _show_list("TRON", count_trx_address(slip39_seed=seed, size=size).trx_slip39_address, size))
    _try_chain("XRP", lambda: _show_list("XRP", count_xrp_address(slip39_seed=seed, size=size).xrp_slip39_address, size))
    _try_chain("ADA", lambda: _print_slip39_ada(count_ada_address(slip39_seed=seed), size))
    _try_chain("LTC", lambda: _print_slip39_ltc(count_ltc_address(slip39_seed=seed, size=size), size))
    _try_chain("BCH", lambda: _show_list("BCH", count_bch_address(slip39_seed=seed, size=size).bch_slip39_address, size))
    _try_chain("APTOS", lambda: _show_list("APTOS", count_apt_address(slip39_seed=seed, size=size).bip44_address, size))
    _try_chain("SUI", lambda: _show_list("SUI", count_sui_address(slip39_seed=seed, size=size).bip44_address, size))
    _try_chain("DASH", lambda: _show_list("DASH", count_dash_address(slip39_seed=seed, size=size).dash_slip39_address, size))
    _try_chain("DOGE", lambda: _show_list("DOGE", count_doge_address(slip39_seed=seed, size=size).doge_slip39_address, size))
    _try_chain("XLM", lambda: _show_list("XLM", count_xlm_address(slip39_seed=seed, size=size).bip44_address, size))
    _try_chain("IOTA", lambda: _show_list("IOTA", count_iota_address(slip39_seed=seed, size=size).bip44_address, size))
    _try_chain("TON SLIP39", lambda: _show_list("TON", count_slip39_ton_address(slip39_seed=seed, size=size).ton_address, size))
    _try_chain("ARWEAVE", lambda: _show_list("AR", count_slip39_arweave_address(slip39_seed=seed, size=size).arweave_address, size))
    _try_chain("COSMOS STYLE", lambda: _print_bip39_cosmos(count_cosmos_address(slip39_byte_seed=seed, change=0, external=0, address_index=0)))
    _try_chain("ZEC", lambda: _print_zec(count_zec_address(slip39_seed=seed, account=0)))


def _print_slip39_btc(value: object, size: int) -> None:
    _show_list("BTC BIP44 Legacy", value.seed_slip44_address, size)
    _show_list("BTC BIP49 Nested SegWit", value.seed_slip49_address, size)
    _show_list("BTC BIP84 Native SegWit", value.seed_slip84_address, size)
    _show_list("BTC BIP86 Taproot", value.seed_slip86_address, size)


def _print_slip39_eth(value: object, size: int) -> None:
    _show_list("ETH BIP44", value.seed_slip44_address, size)
    _show_list("ETH Ledger Live", value.seed_ledger_live_address, size)
    _show_list("ETH Ledger Legacy", value.seed_ledger_legacy_address, size)


def _print_slip39_ada(value: object, size: int) -> None:
    _show_records("ADA Shelley", value.addresses, size)
    _show_records("ADA Enterprise", value.enterprise_addresses, size)


def _print_slip39_ltc(value: object, size: int) -> None:
    _show_list("LTC BIP44", value.ltc_slip44_address, size)
    _show_list("LTC BIP49", value.ltc_slip49_address, size)
    _show_list("LTC BIP84", value.ltc_slip84_address, size)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Derive public addresses for all supported chains.")
    parser.add_argument("--kind", choices=("bip39", "slip39"), default="bip39")
    parser.add_argument("--size", type=int, default=1, help="number of addresses per derivation type")
    parser.add_argument("--env-file", help="optional local env file, for example .env")
    parser.add_argument("--prompt", action="store_true", help="prompt for mnemonic/shares and passphrase")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    _load_env_file(args.env_file)
    size = max(args.size, 1)

    if args.kind == "bip39":
        if args.prompt:
            mnemonic = getpass("BIP39 mnemonic: ").strip()
            passphrase = getpass("BIP39 passphrase, empty if none: ")
        else:
            mnemonic = os.environ.get("BIP39_MNEMONIC", "").strip()
            passphrase = os.environ.get("BIP39_PASSPHRASE", "")
        if not mnemonic:
            raise SystemExit("Set BIP39_MNEMONIC or run with --prompt.")
        derive_bip39(mnemonic, passphrase, size)
        return 0

    if args.prompt:
        shares = getpass("SLIP39 shares, separate shares with literal \\n if needed: ").strip()
        passphrase = getpass("SLIP39 passphrase, empty if none: ")
    else:
        shares = os.environ.get("SLIP39_MNEMONIC", "").strip()
        passphrase = os.environ.get("SLIP39_PASSPHRASE", "")
    if not shares:
        raise SystemExit("Set SLIP39_MNEMONIC or run with --prompt.")
    derive_slip39(shares, passphrase, size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())