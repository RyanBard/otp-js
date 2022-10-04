const { hotp, totp } = require('../otp')

const { expect } = require('chai')

describe('otp', () => {

    const keyStr = '12345678901234567890'

    // https://datatracker.ietf.org/doc/html/rfc4226
    describe('hotp', () => {

        describe('base32 key', () => {

            it('should throw for invalid base32 key char of 1', () => {
                const key = {
                    key: '1RAFOILIBQPR3LOW333VF6DSIQU6M5EN',
                    encoding: 'base32',
                }
                const counter = Buffer.alloc(8, 0)
                expect(() => hotp(key, counter)).to.throw()
            })

            it('should throw for invalid base32 key char of 8', () => {
                const key = {
                    key: '8RAFOILIBQPR3LOW333VF6DSIQU6M5EN',
                    encoding: 'base32',
                }
                const counter = Buffer.alloc(8, 0)
                expect(() => hotp(key, counter)).to.throw()
            })

            it('should throw for invalid base32 key char of 9', () => {
                const key = {
                    key: '9RAFOILIBQPR3LOW333VF6DSIQU6M5EN',
                    encoding: 'base32',
                }
                const counter = Buffer.alloc(8, 0)
                expect(() => hotp(key, counter)).to.throw()
            })

            it('should throw for invalid base32 key char of 0', () => {
                const key = {
                    key: '0RAFOILIBQPR3LOW333VF6DSIQU6M5EN',
                    encoding: 'base32',
                }
                const counter = Buffer.alloc(8, 0)
                expect(() => hotp(key, counter)).to.throw()
            })

            it('should throw for invalid base32 key char of %', () => {
                const key = {
                    key: '%RAFOILIBQPR3LOW333VF6DSIQU6M5EN',
                    encoding: 'base32',
                }
                const counter = Buffer.alloc(8, 0)
                expect(() => hotp(key, counter)).to.throw()
            })

            it('should handle a base32 key', () => {
                const key = {
                    key: '5RAFOILIBQPR3LOW333VF6DSIQU6M5EN',
                    encoding: 'base32',
                }
                const counter = Buffer.alloc(8, 0)
                counter.writeUInt32BE(55226733, 4)
                expect(hotp(key, counter)).to.eql('599865')
            })

            it('should handle a base32 key with spaces', () => {
                const key = {
                    key: '5RAF OILI BQPR 3LOW 333V F6DS IQU6 M5EN',
                    encoding: 'base32',
                }
                const counter = Buffer.alloc(8, 0)
                counter.writeUInt32BE(55226733, 4)
                expect(hotp(key, counter)).to.eql('599865')
            })

        })

        it('should handle a string key', () => {
            const key = keyStr
            const counter = Buffer.alloc(8, 0)
            counter.writeUInt32BE(0, 4)
            expect(hotp(key, counter)).to.eql('755224')
        })

        it('should handle a key without encoding', () => {
            const key = { key: keyStr }
            const counter = Buffer.alloc(8, 0)
            counter.writeUInt32BE(0, 4)
            expect(hotp(key, counter)).to.eql('755224')
        })

        it('should handle step 0', () => {
            const key = keyStr
            const counter = Buffer.alloc(8, 0)
            counter.writeUInt32BE(0, 4)
            expect(hotp(key, counter)).to.eql('755224')
        })

        it('should handle step 1', () => {
            const key = keyStr
            const counter = Buffer.alloc(8, 0)
            counter.writeUInt32BE(1, 4)
            expect(hotp(key, counter)).to.eql('287082')
        })

        it('should handle step 2', () => {
            const key = keyStr
            const counter = Buffer.alloc(8, 0)
            counter.writeUInt32BE(2, 4)
            expect(hotp(key, counter)).to.eql('359152')
        })

        it('should handle step 3', () => {
            const key = keyStr
            const counter = Buffer.alloc(8, 0)
            counter.writeUInt32BE(3, 4)
            expect(hotp(key, counter)).to.eql('969429')
        })

        it('should handle step 4', () => {
            const key = keyStr
            const counter = Buffer.alloc(8, 0)
            counter.writeUInt32BE(4, 4)
            expect(hotp(key, counter)).to.eql('338314')
        })

        it('should handle step 5', () => {
            const key = keyStr
            const counter = Buffer.alloc(8, 0)
            counter.writeUInt32BE(5, 4)
            expect(hotp(key, counter)).to.eql('254676')
        })

        it('should handle step 6', () => {
            const key = keyStr
            const counter = Buffer.alloc(8, 0)
            counter.writeUInt32BE(6, 4)
            expect(hotp(key, counter)).to.eql('287922')
        })

        it('should handle step 7', () => {
            const key = keyStr
            const counter = Buffer.alloc(8, 0)
            counter.writeUInt32BE(7, 4)
            expect(hotp(key, counter)).to.eql('162583')
        })

        it('should handle step 8', () => {
            const key = keyStr
            const counter = Buffer.alloc(8, 0)
            counter.writeUInt32BE(8, 4)
            expect(hotp(key, counter)).to.eql('399871')
        })

        it('should handle step 9', () => {
            const key = keyStr
            const counter = Buffer.alloc(8, 0)
            counter.writeUInt32BE(9, 4)
            expect(hotp(key, counter)).to.eql('520489')
        })

    })

    // https://datatracker.ietf.org/doc/html/rfc6238
    describe('totp', () => {

        describe('base32 key', () => {

            it('should throw for invalid base32 key char of 1', () => {
                const key = {
                    key: '1RAFOILIBQPR3LOW333VF6DSIQU6M5EN',
                    encoding: 'base32',
                }
                expect(() => totp(key)).to.throw()
            })

            it('should throw for invalid base32 key char of 8', () => {
                const key = {
                    key: '8RAFOILIBQPR3LOW333VF6DSIQU6M5EN',
                    encoding: 'base32',
                }
                expect(() => totp(key)).to.throw()
            })

            it('should throw for invalid base32 key char of 9', () => {
                const key = {
                    key: '9RAFOILIBQPR3LOW333VF6DSIQU6M5EN',
                    encoding: 'base32',
                }
                expect(() => totp(key)).to.throw()
            })

            it('should throw for invalid base32 key char of 0', () => {
                const key = {
                    key: '0RAFOILIBQPR3LOW333VF6DSIQU6M5EN',
                    encoding: 'base32',
                }
                expect(() => totp(key)).to.throw()
            })

            it('should throw for invalid base32 key char of %', () => {
                const key = {
                    key: '%RAFOILIBQPR3LOW333VF6DSIQU6M5EN',
                    encoding: 'base32',
                }
                expect(() => totp(key)).to.throw()
            })

            it('should handle a base32 key', () => {
                const key = {
                    key: '5RAFOILIBQPR3LOW333VF6DSIQU6M5EN',
                    encoding: 'base32',
                }
                const getTime = () => 1656801992763
                const result = totp(key, getTime)
                expect(result.token).to.eql('599865')
                expect(result.secondsLeft).to.eql(27)
            })

            it('should handle a base32 key with spaces', () => {
                const key = {
                    key: '5RAF OILI BQPR 3LOW 333V F6DS IQU6 M5EN',
                    encoding: 'base32',
                }
                const getTime = () => 1656801992763
                const result = totp(key, getTime)
                expect(result.token).to.eql('599865')
                expect(result.secondsLeft).to.eql(27)
            })

            it('should show a change of secondsLeft over time', () => {
                const key = {
                    key: '5RAFOILIBQPR3LOW333VF6DSIQU6M5EN',
                    encoding: 'base32',
                }
                const getTime = () => 1656801997763
                const result = totp(key, getTime)
                expect(result.token).to.eql('599865')
                expect(result.secondsLeft).to.eql(22)
            })
        })

        it('should handle default getTime / now', () => {
            const key = keyStr
            const result = totp(key)
            expect(result.token.length).to.eql(6)
            expect(result.secondsLeft).to.be.gte(0)
        })

        it('should handle a string key', () => {
            const key = keyStr
            const getTime = () => 59000
            const result = totp(key, getTime)
            expect(result.token).to.eql('287082')
            expect(result.secondsLeft).to.be.gte(0)
        })

        it('should handle a key without encoding', () => {
            const key = { key: keyStr }
            const getTime = () => 59000
            const result = totp(key, getTime)
            expect(result.token).to.eql('287082')
            expect(result.secondsLeft).to.be.gte(0)
        })

        it('should handle 59s after epoch', () => {
            const key = keyStr
            const getTime = () => 59000
            const result = totp(key, getTime)
            expect(result.token).to.eql('287082')
            expect(result.secondsLeft).to.be.gte(0)
        })

        it('should handle 1111111109s after epoch', () => {
            const key = keyStr
            const getTime = () => 1111111109000
            const result = totp(key, getTime)
            expect(result.token).to.eql('081804')
            expect(result.secondsLeft).to.be.gte(0)
        })

        it('should 1111111111s after epoch', () => {
            const key = keyStr
            const getTime = () => 1111111111000
            const result = totp(key, getTime)
            expect(result.token).to.eql('050471')
            expect(result.secondsLeft).to.be.gte(0)
        })

        it('should 1234567890s after epoch', () => {
            const key = keyStr
            const getTime = () => 1234567890000
            const result = totp(key, getTime)
            expect(result.token).to.eql('005924')
            expect(result.secondsLeft).to.be.gte(0)
        })

        it('should 2000000000s after epoch', () => {
            const key = keyStr
            const getTime = () => 2000000000000
            const result = totp(key, getTime)
            expect(result.token).to.eql('279037')
            expect(result.secondsLeft).to.be.gte(0)
        })

        it('should 20000000000s after epoch', () => {
            const key = keyStr
            const getTime = () => 20000000000000
            const result = totp(key, getTime)
            expect(result.token).to.eql('353130')
            expect(result.secondsLeft).to.be.gte(0)
        })

    })

})
