"use strict";

var crypto = require("crypto");
var eccrypto = require("eccrypto");
var protobuf = require("google-protobuf");
var secp256k1 = require('secp256k1');
var signature = require('./lib/signature');

/**
 * create public key and private key
 */
var createPubPrivateKeys = function createPubPrivateKeys() {
    return signature.createKeys();
};

/**
 * sign message of proto encoded
 * @param {* buffer} protoEncode proto encode buffer 
 * @param {*} privateKey privateKey
 */
var sign = function sign(protoEncode, privateKey) {
    return signature.sign(protoEncode, privateKey);
};

/**
 * verify the public key
 * @param {* buffer} privateKey 
 * @param {* buffer } pubKey 
 */
var isPublicKey = function isPublicKey(privateKey, pubKey) {
    var publicKey = eccrypto.getPublic(privateKey);
    return publicKey.toString('hex') == pubKey.toString('hex');
};

/**
 * verify the sign and signed message
 * @param {* buffer} protoEncode proto encode buffer
 * @param {* buffer} sign sign buffer
 * @param {* buffer} publicKey private key
 */
var verify = function verify(protoEncode, sign, publicKey) {
    var msg = crypto.createHash("sha256").update(undefined.buf2hex(protoEncode.buffer)).digest();
    return secp256k1.verify(msg, sign, publicKey);
};

/**
 * aes encrypto
 * @param {* string} message 
 * @param {* string} secretKey 
 */
var aesEncrypto = function aesEncrypto(message, secretKey) {
    return cryptojs.AES.encrypt(message, secretKey);
};

/**
 * aes decrypto
 * @param {* buffer} aesSecretMessage 
 * @param {* string} secretKey 
 */
var aesDecrypto = function aesDecrypto(aesSecretMessage, secretKey) {
    var bytes = cryptojs.AES.decrypt(aesSecretMessage, secretKey);
    var plaintext = bytes.toString(cryptojs.enc.Utf8);
    return plaintext;
};

module.exports = {
    createPubPrivateKeys: createPubPrivateKeys,
    isPublicKey: isPublicKey,
    sign: sign,
    verify: verify,
    aesEncrypto: aesEncrypto,
    aesDecrypto: aesDecrypto
};
