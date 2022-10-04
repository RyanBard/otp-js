# otp-js
Functions to calculate [HMAC-based One Time Password (HOTP)](https://en.wikipedia.org/wiki/HMAC-based_one-time_password) and [Time-based One Time Password (TOTP)](https://en.wikipedia.org/wiki/Time-based_one-time_password)

## Example Usage

```javascript
const otp = require('@rbard/otp-js')

const key = {key: '5RAFOILIBQPR3LOW333VF6DSIQU6M5EN', encoding: 'base32'}

const {token, secondsLeft} = otp.totp(key)
```

```javascript
const otp = require('@rbard/otp-js')

const key = {key: '5RAFOILIBQPR3LOW333VF6DSIQU6M5EN', encoding: 'base32'}

const counter = Buffer.alloc(8, 0)
counter.writeUInt32BE(55226733, 4)
const token = otp.hotp(key, counter)
```
