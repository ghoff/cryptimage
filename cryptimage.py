from M2Crypto import EVP
import struct, binascii

_encrypt=1
_decrypt=0

def parse_input(data):
	version = ord(data[0])
	keylen = ord(data[1])
	key = data[2:keylen+2]
	cryptlen = ord(data[keylen+2])
	crypt = data[keylen+3:keylen+3+cryptlen]
	return (key, crypt)

def encrypt_data(key, data):
	cipher = EVP.Cipher('aes_128_ecb', key, '', _encrypt)
	cipher.update(data)
	result = cipher.final()
	return(result)


def decrypt_data(key, data):
	cipher = EVP.Cipher('aes_128_ecb', key, '', _decrypt)
	cipher.update(data)
	result = cipher.final()
	return(result)


def compress_key(key):
	if ord(key[0]) != 4:
		raise Exception, "Invalid key"
	if ord(key[-1]) % 2 == 0:
		key = chr(2) + key[1:33]
	else:
		key = chr(3) + key[1:33]
	return(key)


def strip_asn1(der):
	# 2a8648ce3d0201 is OID 1.2.840.10045.2.1 ecPublicKey
	if der[6:13] != binascii.a2b_hex('2a8648ce3d0201'):
		raise Exception, "Invalid ASN.1"
	# strip all but public key
	return(der[26:])


def KDF(key, oBits, P):
	ZB = key
	P = binascii.a2b_hex('082A8648CE3D03010722010800416e6f6e796d6f757353656e646572')+P
	hBits = 256
	threshold = (oBits + hBits - 1) / hBits
	digest = EVP.MessageDigest("sha256")

	counter = 1
	MB = ''
	while True:
		C32 = struct.pack(">i", 1)
		digest.update(C32 + ZB + P)
		HB = digest.digest()
		counter = counter + 1
		MB = MB + HB
		if not (counter <= threshold): break
	return(MB[:oBits/8])


def test():
	len=128
	key = binascii.a2b_hex('79ed88b50d6fa44369ae8effbc5f445160f6c159743188473dc5e3eaceff239e')
	P = binascii.a2b_hex('81e8f11d174054ec6032aeddde6f36bc905e1b1d')
	derived = KDF(key, len, P)
	print binascii.b2a_hex(derived)

if __name__ == "__main__":
	test()
