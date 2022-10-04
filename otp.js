const {
    dynamicTruncate,
    hmac,
} = require('./util')

const defaultTimeStepSize = 30000
const defaultTimeOffset = 0
const defaultNumDigits = 6

// https://datatracker.ietf.org/doc/html/rfc6238
// https://en.wikipedia.org/wiki/Time-based_one-time_password
function totp(key, now = () => Date.now()) {
    const t = Math.floor((now() - defaultTimeOffset) / defaultTimeStepSize)
    const secondsLeft = Math.floor((defaultTimeStepSize - (now() % defaultTimeStepSize)) / 1000)
    const buf = Buffer.alloc(8, 0)
    buf.writeUInt32BE(t, 4)
    const token = hotp(key, buf)
    return {token, secondsLeft}
}

// https://datatracker.ietf.org/doc/html/rfc4226
// https://en.wikipedia.org/wiki/HMAC-based_one-time_password
function hotp(key, counter) {
    const hs = hmac(key, counter)
    const binCode = dynamicTruncate(hs)
    const d = binCode % (10 ** defaultNumDigits)
    return String(d).padStart(6, '0')
}

module.exports = {
    totp,
    hotp,
}
