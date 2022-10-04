const {
    base32Decode,
    base32Encode,
    dynamicTruncate,
    hmac,
} = require('../util')

const { expect } = require('chai')

describe('util', () => {

    // https://datatracker.ietf.org/doc/html/rfc4648
    describe('base32Decode', () => {

        it('should produce known values for test vectors - 1', () => {
            expect(Buffer.from(base32Decode('')).toString('ascii')).to.eql('')
        })

        it('should produce known values for test vectors - 2', () => {
            expect(Buffer.from(base32Decode('MY======')).toString('ascii')).to.eql('f')
        })

        it('should produce known values for test vectors - 3', () => {
            expect(Buffer.from(base32Decode('MZXQ====')).toString('ascii')).to.eql('fo')
        })

        it('should produce known values for test vectors - 4', () => {
            expect(Buffer.from(base32Decode('MZXW6===')).toString('ascii')).to.eql('foo')
        })

        it('should produce known values for test vectors - 5', () => {
            expect(Buffer.from(base32Decode('MZXW6YQ=')).toString('ascii')).to.eql('foob')
        })

        it('should produce known values for test vectors - 6', () => {
            expect(Buffer.from(base32Decode('MZXW6YTB')).toString('ascii')).to.eql('fooba')
        })

        it('should produce known values for test vectors - 7', () => {
            expect(Buffer.from(base32Decode('MZXW6YTBOI======')).toString('ascii')).to.eql('foobar')
        })

    })

    // https://datatracker.ietf.org/doc/html/rfc4648
    describe('base32Encode', () => {

        it('should produce known values for test vectors - 1', () => {
            expect(base32Encode(Buffer.from('', 'ascii'))).to.eql('')
        })

        it('should produce known values for test vectors - 2', () => {
            expect(base32Encode(Buffer.from('f', 'ascii'))).to.eql('MY======')
        })

        it('should produce known values for test vectors - 3', () => {
            expect(base32Encode(Buffer.from('fo', 'ascii'))).to.eql('MZXQ====')
        })

        it('should produce known values for test vectors - 4', () => {
            expect(base32Encode(Buffer.from('foo', 'ascii'))).to.eql('MZXW6===')
        })

        it('should produce known values for test vectors - 5', () => {
            expect(base32Encode(Buffer.from('foob', 'ascii'))).to.eql('MZXW6YQ=')
        })

        it('should produce known values for test vectors - 6', () => {
            expect(base32Encode(Buffer.from('fooba', 'ascii'))).to.eql('MZXW6YTB')
        })

        it('should produce known values for test vectors - 7', () => {
            expect(base32Encode(Buffer.from('foobar', 'ascii'))).to.eql('MZXW6YTBOI======')
        })

    })

    // https://datatracker.ietf.org/doc/html/rfc4226
    describe('dynamicTruncate', () => {

        it('should produce a known value for a known input', () => {
            const buf = Buffer.from('1F8698690E02CA16618550EF7F19DA8E945B555A', 'hex')
            
            expect(dynamicTruncate(buf)).to.eql(0x50ef7f19)
        })

    })

    // https://datatracker.ietf.org/doc/html/rfc2202#section-3
    describe('hmac', () => {

        it('should perform a hmac-sha1 hash - 1', () => {
            const key = {
                key: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
                encoding: 'hex',
            }
            const message = 'Hi There'
            const result = hmac(key, message)
            expect(result.toString('hex')).to.eql('b617318655057264e28bc0b6fb378c8ef146be00')
        })

        it('should perform a hmac-sha1 hash - 2', () => {
            const key = 'Jefe'
            const message = 'what do ya want for nothing?'
            const result = hmac(key, message)
            expect(result.toString('hex')).to.eql('effcdf6ae5eb2fa2d27416d5f184df9c259a7c79')
        })

        it('should perform a hmac-sha1 hash - 3', () => {
            const key = {
                key: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                encoding: 'hex',
            }
            const message = Buffer.from('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', 'hex')
            const result = hmac(key, message)
            expect(result.toString('hex')).to.eql('125d7342b9ac11cd91a39af48aa17b4f63f175d3')
        })

        it('should perform a hmac-sha1 hash - 4', () => {
            const key = {
                key: '0102030405060708090a0b0c0d0e0f10111213141516171819',
                encoding: 'hex',
            }
            const message = Buffer.from('cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd', 'hex')
            const result = hmac(key, message)
            expect(result.toString('hex')).to.eql('4c9007f4026250c6bc8414f9bf50c86c2d7235da')
        })

        it('should perform a hmac-sha1 hash - 5', () => {
            const key = {
                key: '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
                encoding: 'hex',
            }
            const message = 'Test With Truncation'
            const result = hmac(key, message)
            expect(result.toString('hex')).to.eql('4c1a03424b55e07fe7f27be1d58bb9324a9a5a04')
        })

        it('should perform a hmac-sha1 hash - 6', () => {
            const key = {
                key: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                encoding: 'hex',
            }
            const message = 'Test Using Larger Than Block-Size Key - Hash Key First'
            const result = hmac(key, message)
            expect(result.toString('hex')).to.eql('aa4ae5e15272d00e95705637ce8a3b55ed402112')
        })

        it('should perform a hmac-sha1 hash - 7', () => {
            const key = {
                key: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                encoding: 'hex',
            }
            const message = 'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data'
            const result = hmac(key, message)
            expect(result.toString('hex')).to.eql('e8e99d0f45237d786d6bbaa7965c7808bbff1a91')
        })

    })

})
