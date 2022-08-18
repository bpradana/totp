import hashlib
import time
import hmac


class TOTP:
    def generate_token(self, key, digits=6, algorithm='SHA1', period=30, timestamp=time.time()):
        hash_function = {
            'SHA1': hashlib.sha1,
            'SHA256': hashlib.sha256,
            'SHA512': hashlib.sha512
        }

        key = self._str_to_base32(key)
        key = self._base32_to_hex(key)
        epoch = int(timestamp)
        time_step = self._dec_to_hex(epoch // period).rjust(16, '0')

        hash_function = hash_function[algorithm]
        hash_function = hmac.new(
            bytearray.fromhex(key), bytearray.fromhex(time_step), hash_function)
        hex_hash = hash_function.hexdigest()
        offset = int(hex_hash[-1], 16)
        otp = int(hex_hash[offset * 2:offset * 2 + 8], 16)
        otp = otp % (10 ** digits)
        otp = str(otp).rjust(digits, '0')

        return otp

    def _hex_to_dec(self, hex_string):
        return int(hex_string, 16)

    def _dec_to_hex(self, dec_string):
        return '{:x}'.format(dec_string)

    def _base32_to_hex(self, base32_string):
        base32_characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
        bits = ''
        hex = ''

        base32_string = base32_string.rstrip('=')

        for i in range(len(base32_string)):
            val = base32_characters.index(base32_string[i].upper())
            if val == -1:
                raise ValueError("Invalid base32 character in key")
            bits += format(val, 'b').rjust(5, '0')

        for i in range(0, len(bits)-8, 8):
            chunk = bits[i:i+8]
            hex += '{:x}'.format(int(chunk, 2)).rjust(2, '0')

        return hex

    def _str_to_base32(self, string):
        base32_characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
        bits = ''
        base32 = ''

        for i in range(len(string)):
            bits += format(ord(string[i]), 'b').rjust(8, '0')

        for i in range(0, len(bits), 5):
            chunk = bits[i:i+5].ljust(5, '0')
            base32 += base32_characters[int(chunk, 2)]

        return base32.ljust(len(string)+(len(string) % 8), '=')
