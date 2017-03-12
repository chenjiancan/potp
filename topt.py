import hashlib
import hmac
from hmac import new as Hmac
import binascii

import logging

logging.basicConfig(filename='log', filemode='a', format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S', level=logging.INFO)

logger = logging.getLogger(__name__)


class Topt(object):
    def __init__(self, secret, digits, x=30, mode=hashlib.sha256):
        self.secret = secret
        self.digits = digits
        self.x = x
        self.mode = mode
        hash_key_len = 0
        if mode == hashlib.sha256:
            hash_key_len = 32
        if mode == hashlib.sha512:
            hash_key_len = 64
        if mode == hashlib.sha1:
            hash_key_len = 20

        secret_len_r = hash_key_len * 2 - len(secret)
        if secret_len_r > 0:
            secret = '0' * secret_len_r + secret
        self.secret = binascii.a2b_hex(secret)
        logger.info(('self.secret : %s len: %d' % (self.secret, len(self.secret))))
        self.mac = Hmac(self.secret, digestmod=self.mode)

    def digest(self, msg):
        mac = self.mac.copy()
        mac.update(msg)

        bytes_hash = mac.digest()
        logger.info(('hashed:', bytes_hash, 'len:', len(bytes_hash)))

        return bytes_hash

    def dynamic_truncate(self, hash_bytes):
        offset = hash_bytes[-1] & 0x0f
        dyn_truncated = 0
        for i in range(4):
            dyn_truncated += (hash_bytes[offset + i] & 0xff) << 8 * (4 - 1 - i)
        dyn_truncated &= ~(0x01 << (8 * 4 - 1))

        logger.info(('offset:', offset, 'dyn_truncated:', dyn_truncated))
        return dyn_truncated

    def truncate(self, digest):
        dyn_truncated = self.dynamic_truncate(digest)
        truncated = dyn_truncated % (10 ** self.digits)
        logger.info(('truncated: ', truncated))
        return truncated

    def generateTotp(self, T: int):
        steps = T // self.x
        steps_hex_bytes = steps.to_bytes(8, 'big', signed=False)
        logger.info(('steps_hex_bytes:', steps_hex_bytes))

        hashed = self.digest(steps_hex_bytes)
        opt_int = self.truncate(hashed)
        opt_str = str(opt_int)
        opt_str = '0' * (self.digits - len(opt_str)) + opt_str
        return opt_str

    def generateTotp_now(self):

        import datetime
        utcnow = datetime.datetime.utcnow()
        T = utc = utcnow.timestamp()
        logger.info('utc now: %s  %d' % (utcnow, T,))
        return self.generateTotp(int(T))


def test(key, T, digits=8, mode=hashlib.sha256):
    X = 30
    totp = Topt(key, digits, X, mode)
    logger.info(('totp: key: %s, digits:%d, X:%d' % (totp.secret, totp.digits, totp.x)))
    otp = totp.generateTotp(T)
    logger.info(('Topt :', otp))
    return otp


def test_rfc_case():

    rfc6238_test_case = (
        (hashlib.sha256, 59, "46119246"),
        (hashlib.sha256, 1111111109, "68084774"),
        (hashlib.sha256, 1111111111, "67062674"),
        (hashlib.sha256, 1234567890, "91819424"),
        (hashlib.sha256, 2000000000, "90698825"),
        (hashlib.sha256, 20000000000, "77737706"),
    )

    for case in rfc6238_test_case:
        result = test(key, case[1], 8, case[0])
        assert result == case[2]
    print("test passed!")

def test_real_time():
    import time
    totp = Topt(key, 6, 30)
    while True:
        print(totp.generateTotp_now())
        print('____________________________')
        time.sleep(totp.x)

if __name__ == '__main__':


    key = "3132333435363738393031323334353637383930313233343536373839303132"

    test_rfc_case()

    test_real_time()