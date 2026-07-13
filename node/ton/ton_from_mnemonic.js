// ton_from_mnemonic.js

// 依赖: npm install tonweb bip39 ed25519-hd-key tweetnacl

const TonWeb = require("tonweb");
const bip39 = require("bip39");
const { derivePath } = require("ed25519-hd-key");
const nacl = require("tweetnacl");

// BIP44 path for TON: m/44'/607'/0'
const path = "m/44'/607'/0'";

async function main() {
    try {
        // 从命令行参数获取助记词和 passphrase
        const mnemonic = process.argv[2];
        const passphrase = process.argv[3] || "";
        
        if (!mnemonic) {
            console.error("错误: 请提供助记词作为第一个参数");
            process.exit(1);
        }
        
        const seed = await bip39.mnemonicToSeed(mnemonic, passphrase); // Buffer
        const { key } = derivePath(path, seed.toString("hex")); // ed25519 私钥 (32 bytes)
        
        // 从私钥生成公钥（使用 tweetnacl）
        const keyPair = nacl.sign.keyPair.fromSeed(key);
        const pubKeyBytes = new Uint8Array(keyPair.publicKey);

        // 创建 TonWeb 实例（需要 provider）
        const tonweb = new TonWeb(new TonWeb.HttpProvider());
        
        // 使用 TonWeb.Wallets 创建 V4R2 钱包
        const Wallets = TonWeb.Wallets;
        const WalletClass = Wallets.all.v4R2;
        const wallet = new WalletClass(tonweb.provider, {
            publicKey: pubKeyBytes,
            wc: 0  // workchain 0 (主网)
        });
        
        // 获取地址（使用 getAddress 方法）
        const address = await wallet.getAddress();
        
        // 硬件钱包使用 URL-safe Base64 格式（第二个参数为 true，+ 变成 -，/ 变成 _）
        const bounceableAddr = address.toString(true, true);  // bounceable, mainnet, url-safe
        
        console.log(bounceableAddr);
    } catch (e) {
        console.error(e);
        process.exit(1);
    }
}

main();

