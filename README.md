# gravity-contract-near-rust

Gravity's Smart Contract for NEAR using Rust

# What This Contract Does

Stores unique records for evidence of signing Terms of Service for [**GRVTY**](https://grvty.tech/).
<br />

# Quickstart

Clone this repository locally or [**open it in GitHub**](https://github.com/ReCheck-io/gravity-contract-near-rust).

```bash
git clone git@github.com:ReCheck-io/gravity-contract-near-rust.git
```

Then follow these steps inside the repo directory:

### 1. Install Dependencies

Install Rust from the [**installer script**](https://rustup.rs).

```bash
curl https://sh.rustup.rs/ -sSf | sh
```

Set the required target.

```bash
rustup target add wasm32-unknown-unknown
```

### 2. Build the Contract

Build the contract.

```bash
RUSTFLAGS='-C link-arg=-s' cargo build --target wasm32-unknown-unknown --release
```

Run contract tests and verify they pass.

```bash
cargo test
```

### 3. Deploy the Contract using NEAR CLI

Install [**NEAR CLI**](https://github.com/near/near-cli)

```bash
npm install -g near-cli
```

By default, it is set for "testnet". For "mainnet" set it like this.

```bash
export NEAR_ENV=mainnet
```

You can verify it to be sure.

```bash
echo $NEAR_ENV
```

Login with your NEAR wallet.

```bash
near login
```

Deploy the contract using a new testnet account.

```bash
near dev-deploy ./target/wasm32-unknown-unknown/release/gravity_near.wasm
```

For mainnet you can create a sub account first.

```bash
near create-account SUB-ACCOUNT.YOUR-WALLET-ID.near --masterAccount YOUR-WALLET-ID.near --initialBalance DESIRED-AMMOUNT
```

And then deploy with the sub account.

```bash
near deploy YOUR-NEW-ACCOUNT.near ./target/wasm32-unknown-unknown/release/gravity_near.wasm
```

Any sub account can be added to your wallet with its private key.

```bash
https://wallet.near.org/auto-import-secret-key#YOUR_ACCOUNT_ID/YOUR_PRIVATE_KEY
```

All account keys are located here.

```bash
cd ~/.near-credentials
```

If any of the steps fails due to low balance use this formula to convert yocto to near.

```bash
X yocto / 10^24 = Y NEAR
```

### 4. Interact with the Contract using NEAR CLI

Execute change method (*you have to be logged in with the **same** NEAR wallet used for deployment*)

```bash
near call --accountId YOUR-WALLET-ID.TESTNET ACCOUNT-USED-FOR-DEPLOYMENT signTerms '{"signer_string":"SET_HASH_VALUE","signer_signature_string":"SET_HEX_VALUE","terms_hash_string":"SET_HASH_VALUE"}'
```

Execute view method (*with **any** logged in wallet*)

```bash
near view --accountId ANY-WALLET-ID.TESTNET ACCOUNT-USED-FOR-DEPLOYMENT validateSignature '{"signer_string":"SET_HASH_VALUE","terms_hash_string":"SET_HASH_VALUE"}'
```

---

# Learn More

1. Learn more about the contract through its [**README**](./README.md).
2. Check our [**website**](https://grvty.tech) for more information about us.
