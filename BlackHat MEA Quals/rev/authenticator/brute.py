from wincrypto import CryptCreateHash, CryptHashData, CryptDeriveKey, CryptEncrypt, CryptDecrypt
from wincrypto.constants import CALG_MD5, CALG_AES_128, bType_SIMPLEBLOB
from binascii import unhexlify

enc_flag = "73E3679507CC8197F665FD5B46F55321CF89BB828CD7BB424B181734D468709709D49085868CDA1B9892B947999E4F64"
for first in range(7):
    for second in range(3):
        for third in range(9):
            for fourth in range(6):
                for fifth in range(9):
                    for sixth in range(8):
                        for seventh in range(4):
                            for eigth in range(5):
                                data = str(first).encode() + str(second).encode() + str(third).encode() + str(fourth).encode() + str(fifth).encode() + str(sixth).encode() + str(seventh).encode() + str(eigth).encode()
                                md5_hasher = CryptCreateHash(CALG_MD5)
                                CryptHashData(md5_hasher, data)
                                aes_key = CryptDeriveKey(md5_hasher, CALG_AES_128)
                                pt = CryptDecrypt(aes_key, bytes.fromhex(enc_flag))
                                if b"BHFlagY" in pt:
                                    print(pt)
                                    exit()


#BHFlagY{ca11ing_n4tiv3_c0d3_fr0m_j5_vb5_ps}