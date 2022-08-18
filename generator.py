from totp import TOTP
import time


if __name__ == '__main__':
    totp = TOTP()

    KEY = 'SECRET KEY'
    DIGITS = 6
    ALGORITHM = 'SHA512'
    PERIOD = 5

    otp = ''
    while True:
        new_otp = totp.generate_token(
            key=KEY,
            digits=DIGITS,
            period=PERIOD,
            algorithm=ALGORITHM,
            timestamp=time.time()
        )
        if otp != new_otp:
            print(new_otp)
            otp = new_otp
