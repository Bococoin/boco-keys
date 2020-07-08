import * as bip39 from 'bip39'
// @ts-ignore
import * as bip32 from 'bip32'
import * as bech32 from 'bech32'
import * as secp256k1 from 'secp256k1'
import * as CryptoJS from 'crypto-js'
import * as util from 'util'
import { Wallet, StdSignMsg,StdSignandverifyMsg, KeyPair } from './types';
import { decode } from 'punycode'

const hdPathAtom = `m/44'/3020'/0'/0/0` // key controlling BCC allocation

/* tslint:disable-next-line:strict-type-predicates */
const windowObject: Window | null = typeof window === 'undefined' ? null : window
const createHash = require('create-hash')
// returns a byte buffer of the size specified
export function randomBytes(size: number, window = windowObject): Buffer {
  // in browsers
  if (window && window.crypto) {
    return windowRandomBytes(size, window)
  }

  try {
    // native node crypto
    const crypto = require('crypto')
    return crypto.randomBytes(size)
  } catch (err) {
    // no native node crypto available
  }

  throw new Error(
    'There is no native support for random bytes on this system. Key generation is not safe here.'
  )
}

export function getNewWalletFromSeed(mnemonic: string): Wallet {
  const masterKey = deriveMasterKey(mnemonic)
  const { privateKey, publicKey } = deriveKeypair(masterKey)
  const cosmosAddress = getCosmosAddress(publicKey)
  return {
    privateKey: privateKey.toString('hex'),
    publicKey: publicKey.toString('hex'),
    cosmosAddress
  }
}

export function getSeed(randomBytesFunc: (size: number) => Buffer = randomBytes): string {
  const entropy = randomBytesFunc(32)
  if (entropy.length !== 32) throw Error(`Entropy has incorrect length`)
  const mnemonic = bip39.entropyToMnemonic(entropy.toString('hex'))

  return mnemonic
}

export function getNewWallet(randomBytesFunc: (size: number) => Buffer = randomBytes): Wallet {
  const mnemonic = getSeed(randomBytesFunc)
  return getNewWalletFromSeed(mnemonic)
}

// NOTE: this only works with a compressed public key (33 bytes)
export function getCosmosAddress(publicKey: Buffer): string {
  const message = CryptoJS.enc.Hex.parse(publicKey.toString('hex'))
  const address = CryptoJS.RIPEMD160(CryptoJS.SHA256(message) as any).toString()
  const cosmosAddress = bech32ify(address, `boco`)
  return cosmosAddress
}

function deriveMasterKey(mnemonic: string): bip32.BIP32 {
  // throws if mnemonic is invalid
  bip39.validateMnemonic(mnemonic)

  const seed = bip39.mnemonicToSeedSync(mnemonic)
  const masterKey = bip32.fromSeed(seed)
  return masterKey
}

// @ts-ignore
function deriveKeypair(masterKey: bip32.BIP32): KeyPair {
  const cosmosHD = masterKey.derivePath(hdPathAtom)
  const privateKey = cosmosHD.privateKey
  const publicKey = secp256k1.publicKeyCreate(privateKey, true)
  return {
    privateKey,
    // @ts-ignore
    publicKey
  }
}

// converts a string to a bech32 version of that string which shows a type and has a checksum
function bech32ify(address: string, prefix: string) {
  const words = bech32.toWords(Buffer.from(address, 'hex'))
  return bech32.encode(prefix, words)
}
// produces the signature for a message (returns Buffer)
export function signWithPrivateKey(signMessage: StdSignMsg | string, privateKey: Buffer): Buffer {
  const signMessageString: string =
    typeof signMessage === 'string' ? signMessage : JSON.stringify(signMessage)
  const signHash = Buffer.from(CryptoJS.SHA256(signMessageString).toString(), `hex`)
  // @ts-ignore
  const { signature } = secp256k1.sign(signHash, privateKey)

  return signature
}
// produces the signature for a message (returns Buffer)
export function signWithPrivateKeywallet(signMessage: StdSignandverifyMsg | string, privateKey: Buffer): Buffer {
  const signMessageString: string =
    typeof signMessage === 'string' ? signMessage : JSON.stringify(signMessage.message)
  const signHash = Buffer.from(CryptoJS.SHA256(signMessageString).toString(), `hex`)
  // @ts-ignore
  const { signature,recovery } = secp256k1.sign(signHash, privateKey)
  var len = signature.length
  const signatureconcatenated = Buffer.concat([signature, Buffer.from(recovery.toString())])
  return signatureconcatenated
}

//Verify
export function verifySignature(signMessage: StdSignandverifyMsg | string, signature: Buffer, publicKey: Buffer): boolean {
  var recoverBit = 0
  const signMessageString: string =
    typeof signMessage === 'string' ? signMessage : JSON.stringify(signMessage.message)
  const signHash = Buffer.from(CryptoJS.SHA256(signMessageString).toString(), `hex`)
  const hash =  magicHash(signMessageString,'boco')
  var sig = signature.slice(0,signature.length-1)
  var chk = signature.slice(signature.length-1,signature.length)
  if(parseInt(chk.toString()) >= 0){
    recoverBit = parseInt(chk.toString())
  }
  // @ts-ignore
  var extractedpublicKey = secp256k1.recover(signHash, sig, recoverBit, true)
  const extractedbocoaddress = Buffer.from(getCosmosAddress(extractedpublicKey), 'base64')
  if (Buffer.compare(publicKey,extractedbocoaddress) != 0){
    return false
  }
  // @ts-ignore
  return secp256k1.verify(signHash, sig,extractedpublicKey)
}


function windowRandomBytes(size: number, window: Window) {
  const chunkSize = size / 4
  let hexString = ''
  let keyContainer = new Uint32Array(chunkSize)
  keyContainer = window.crypto.getRandomValues(keyContainer)

  for (let keySegment = 0; keySegment < keyContainer.length; keySegment++) {
    let chunk = keyContainer[keySegment].toString(16) // Convert int to hex
    while (chunk.length < chunkSize) {
      // fill up so we get equal sized chunks
      chunk = '0' + chunk
    }
    hexString += chunk // join
  }
  return Buffer.from(hexString, 'hex')
}

function convert (data:any, inBits:any, outBits:any, pad:any) {
  var value = 0
  var bits = 0
  var maxV = (1 << outBits) - 1

  var result = []
  for (var i = 0; i < data.length; ++i) {
    value = (value << inBits) | data[i]
    bits += inBits

    while (bits >= outBits) {
      bits -= outBits
      result.push((value >> bits) & maxV)
    }
  }

  if (pad) {
    if (bits > 0) {
      result.push((value << (outBits - bits)) & maxV)
    }
  } else {
    if (bits >= inBits) throw new Error('Excess padding')
    if ((value << (outBits - bits)) & maxV) throw new Error('Non-zero padding')
  }

  return result
}

function magicHash (message:any, messagePrefix:any) {
  const varuint = require('varuint-bitcoin')
  messagePrefix = messagePrefix || '\u0018Bitcoin Signed Message:\n'
  if (!Buffer.isBuffer(messagePrefix)) {
    messagePrefix = Buffer.from(messagePrefix, 'utf8')
  }

  const messageVISize = varuint.encodingLength(message.length)
  const buffer = Buffer.allocUnsafe(
    messagePrefix.length + messageVISize + message.length
  )
  messagePrefix.copy(buffer, 0)
  varuint.encode(message.length, buffer, messagePrefix.length)
  buffer.write(message, messagePrefix.length + messageVISize)
  const buffermessage = CryptoJS.enc.Hex.parse(buffer.toString('hex'))
  return hash256(buffermessage)
}

function hash256 (buffer:any) {
  return CryptoJS.SHA256(buffer)
}
