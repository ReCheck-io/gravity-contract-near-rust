# recheck-contract-near-rust

Gravity's Smart Contract for NEAR using Rust

# What This Contract Does

Stores unique records for evidence of signing Terms of Service for [**GRVTY**](https://grvty.tech/).
<br />

# Quickstart

Clone this repository locally or [**open it in GitHub**](https://github.com/ReCheck-io/gravity-contract-near-rust). Then
follow these steps:

### 1. Install Dependencies

```bash
npm install
```

### 2. Build the Contract

Build the contract.

```bash
RUSTFLAGS='-C link-arg=-s' cargo build --target wasm32-unknown-unknown --release
```

### 2. Run all tests

Run contract tests and verify they pass.

```bash
cargo test
```

### 3. Deploy the Contract using NEAR CLI

Install [**NEAR CLI**](https://github.com/near/near-cli)

```bash
npm install -g near-cli
```

Login with your NEAR wallet.

```bash
near login
```

Deploy the contract using a new testnet account.

```bash
near dev-deploy ./target/wasm32-unknown-unknown/release/gravity_near.wasm
```

### 4. Interact with the Contract using NEAR CLI

Execute change method (*you have to be logged in with the **same** NEAR wallet used for deployment*)

```bash
near call --accountId YOUR-WALLET-ID.TESTNET DEV-ACCOUNT-USED-FOR-DEPLOYMENT signTerms '{"signer_string":"SET_HASH_VALUE","signer_signature_string":"SET_HEX_VALUE","terms_hash_string":"SET_HASH_VALUE"}'
```

Execute view method (*with **any** logged in wallet*)

```bash
near call --accountId ANY-WALLET-ID.TESTNET ANY-ACCOUNT validateSignature '{"signer_string":"SET_HASH_VALUE","terms_hash_string":"SET_HASH_VALUE"}'
```

---

# Learn More

1. Learn more about the contract through its [**README**](./README.md).
2. Check our [**website**](https://grvty.tech) for more information about us.
