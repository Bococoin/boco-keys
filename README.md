# Boco Keys

Boco Keys is a library for creating keys and signing messages on Boco. You can use it to generate keypairs and addresses and to sign messages for the Boco Network. 

This library deals with tasks that are considered *security-critical* and should be used very carefully.

## Install

```bash
yarn add @bococoin/boco-keys
```

## Usage

### Create a wallet

```js
import { getNewWallet } from "@bococoin/boco-keys"

const { BocoAddress, privateKey, publicKey } = getNewWallet()
// Attention: protect the `privateKey` at all cost and never display it anywhere!!
```

### Import a seed

```js
import { generateWalletFromSeed } from "@bococoin/boco-keys"

const seed = ...24 seed words here

const { BocoAddress, privateKey, publicKey } = generateWalletFromSeed(seed)
// Attention: protect the `privateKey` at all cost and never display it anywhere!!
```

### Sign a message

```js
import { signWithPrivateKey } from "@bococoin/boco-keys"

const privateKey = Buffer.from(...)
const signMessage = ... message to sign, generate messages with "@lunie/Cosmos-js"
const signature = signWithPrivateKey(signMessage, privateKey)

```

### Using with Boco-js

```js
import { signWithPrivateKey } from "@bococoin/boco-keys"
import Boco from "@lunie/Cosmos-js"

const privateKey = Buffer.from(...)
const publicKey = Buffer.from(...)

// init Boco sender
const Boco = Boco(STARGATE_URL, ADDRESS)

// create message
const msg = Boco
  .MsgSend({toAddress: 'boco1abcd09876', amounts: [{ denom: 'ubcc', amount: 10 }})

// create a signer from this local js signer library
const localSigner = (signMessage) => {
  const signature = signWithPrivateKey(signMessage, privateKey)

  return {
    signature,
    publicKey
  }
}

// send the transaction
const { included }= await msg.send({ gas: 200000 }, localSigner)

// await tx to be included in a block
await included()
```
