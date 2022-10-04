const crypto = require('crypto')
const base32 = require('hi-base32')

// https://www.rfc-editor.org/rfc/rfc4226#section-5.4
// https://en.wikipedia.org/wiki/HMAC-based_one-time_password
function dynamicTruncate(hs) {
    const offset = hs.readUInt8(hs.length - 1) & 0xF
    const binCode = (hs.readUInt8(offset) & 0x7F) << 24
        | (hs.readUInt8(offset + 1) & 0xFF) << 16
        | (hs.readUInt8(offset + 2) & 0xFF) << 8
        | (hs.readUInt8(offset + 3) & 0xFF)
    return binCode
}

function hmac(secret, message) {
    let decodedSecret
    if (typeof secret === 'string') {
        decodedSecret = secret
    } else if (!secret.encoding) {
        decodedSecret = secret.key
    } else if (secret.encoding === 'base32') {
        const wsStripped = secret.key.replace(/ /g, '')
        const decoded = base32Decode(wsStripped)
        decodedSecret = Buffer.from(decoded)
    } else {
        decodedSecret = Buffer.from(secret.key, secret.encoding)
    }
    return crypto
        .createHmac('sha1', decodedSecret)
        .update(message)
        .digest()
}

// https://datatracker.ietf.org/doc/html/rfc4648
// https://en.wikipedia.org/wiki/Base32 - RFC 4648
// https://www.npmjs.com/package/hi-base32
// https://github.com/emn178/hi-base32
function base32Encode(buf) {
    return base32.encode(buf)
}

function base32Decode(str) {
    return base32.decode.asBytes(str)
}

module.exports = {
    base32Decode,
    base32Encode,
    dynamicTruncate,
    hmac,
}
