var crypto = require("crypto");
var eccrypto = require("eccrypto");
var protobuf = require("google-protobuf");
const secp256k1 = require('secp256k1')
const signature = require('./lib/signature')

/**
 * create public key and private key
 */
const createPubPrivateKeys = ()=>{
    return signature.createKeys()
}

/**
 * sign message of proto encoded
 * @param {* buffer} protoEncode proto encode buffer 
 * @param {*} privateKey privateKey
 */
const sign = (protoEncode,privateKey)=>{
    return signature.sign(protoEncode,privateKey)
}

/**
 * verify the public key
 * @param {* buffer} privateKey 
 * @param {* buffer } pubKey 
 */
const isPublicKey = (privateKey,pubKey)=>{
    let publicKey = eccrypto.getPublic(privateKey)
    return publicKey.toString('hex')==pubKey.toString('hex')
}

/**
 * verify the sign and signed message
 * @param {* buffer} protoEncode proto encode buffer
 * @param {* buffer} sign sign buffer
 * @param {* buffer} publicKey private key
 */
const verify = (protoEncode,sign,publicKey)=>{
    let msg = crypto.createHash("sha256").update(this.buf2hex(protoEncode.buffer)).digest()
    return secp256k1.verify(msg,sign,publicKey)
}

/**
 * aes encrypto
 * @param {* string} message 
 * @param {* string} secretKey 
 */
const aesEncrypto = (message,secretKey)=>{
    return cryptojs.AES.encrypt(message, secretKey);
}

/**
 * aes decrypto
 * @param {* buffer} aesSecretMessage 
 * @param {* string} secretKey 
 */
const aesDecrypto = (aesSecretMessage, secretKey)=>{
    let bytes  = cryptojs.AES.decrypt(aesSecretMessage, secretKey);
    let plaintext = bytes.toString(cryptojs.enc.Utf8);
    return plaintext;
}


module.exports = {
    createPubPrivateKeys,
    isPublicKey,
    sign,
    verify,
    aesEncrypto,
    aesDecrypto
}
