# Address Count

Address Count is a local address derivation toolkit for calculating chain addresses from BIP39 and SLIP39 inputs.

It keeps only the address calculation surface from the original workspace: BIP39 address calculation, SLIP39 address calculation, the TON BIP39 helper, and the small Rust FFI used by Arweave address generation.

## Project Layout

```text
src/address_derivation/      Chain address calculators for BIP39 and SLIP39 inputs
node/ton/                    TON BIP39 helper implemented with Node.js
crates/rust_rsa_ffi/         Arweave RSA prime generation FFI
requirements.txt             Python runtime dependencies
.env.example                 Safe environment variable template
```

Large generated assets, signing experiments, Keystone source trees, build outputs, and local secrets are intentionally excluded from this repository.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd node/ton && npm install
cd ../../crates/rust_rsa_ffi && cargo build --release
```

## Usage

Calculate BIP39 addresses:

```bash
export BIP39_MNEMONIC="your mnemonic here"
export TON_MNEMONIC="your ton mnemonic here"
python src/address_derivation/bip39_address.py
```

Calculate SLIP39 addresses:

```bash
export SLIP39_MNEMONIC="share one\nshare two\nshare three"
python src/address_derivation/slip39_address.py
```

Calculate a TON address from an explicit mnemonic argument:

```bash
node node/ton/ton_from_mnemonic.js "your mnemonic here"
```

## Supported Chains

The BIP39 and SLIP39 modules include address calculators for BTC, ETH/EVM, SOL, AVAX, TRON, XRP, ADA, LTC, BCH, APTOS, SUI, DASH, DOGE, XLM, IOTA, TON, Arweave, Monero, Cosmos-style addresses, and Zcash.

Arweave address calculation requires the Rust FFI dynamic library built from `crates/rust_rsa_ffi`.

Zcash transparent address calculation is built in. Zcash unified address calculation requires `zcash_vendor_py` or a compatible local Rust Zcash helper on `PATH`.

## Security

Do not commit real seed phrases, SLIP39 shares, private keys, generated wallet exports, or local output files. Use `.env` for local values and keep `.env.example` as a placeholder-only template.
