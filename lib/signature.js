var crypto = require("crypto");
var eccrypto = require("eccrypto");
var protobuf = require("google-protobuf");
const secp256k1 = require('secp256k1')

/**
 * buffer type to string
 * @param {* buffer} buffer 
 */
exports.buf2hex = (buffer)=>{
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

/**
 * create publicKey and privateKey
 */
exports.createKeys = ()=>{
    let privateKey = crypto.randomBytes(32)
    let publicKey = eccrypto.getPublic(privateKey)

    return {privateKey,publicKey}
}

/**
 * 
 * @param {* buffer} privateKey privateKey  
 * @param {* buffer} pubKey pubic key
 */
exports.isPublicKey = (privateKey,pubKey)=>{
    let publicKey = eccrypto.getPublic(privateKey)
    return publicKey.toString('hex')==pubKey.toString('hex')
}

/**
 * sign the messages return buffer 
 * @param {* buffer} protoEncode proto encodeed buffer
 * @param {* buffer} privateKey created by createKeys
 */
exports.sign = (protoEncode,privateKey)=>{
    let msg = crypto.createHash("sha256").update(this.buf2hex(protoEncode.buffer)).digest()
    const signObj = secp256k1.sign(msg,privateKey)
    return signObj.signature;
}

/**
 * create proto buffer by protojs and json message
 * @param {*proto file in javascript} protojs 
 * @param {* JSON Object} msg message for sign
 */
exports.protobufEncode = (protojs,msg)=>{
    const ProtoMsg = new protojs.Message()

    ProtoMsg.setVersion(msg.version)
    ProtoMsg.setCursornum(msg.cursornum)
    ProtoMsg.setCursorlabel(msg.cursorlabel)
    ProtoMsg.setLifetime(msg.lifetime)
    ProtoMsg.setSender(msg.sender)
    ProtoMsg.setContract(msg.contract)
    ProtoMsg.setMethod(msg.method)
    ProtoMsg.setParam(new Uint8Array(msg.param))
    ProtoMsg.setSigalg(msg.sigalg)
    ProtoMsg.setSignature(msg.signature)

    return ProtoMsg.serializeBinary();
}
