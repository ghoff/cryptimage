from M2Crypto import EVP
import struct, binascii, dpd

_encrypt=1
_decrypt=0

#not done yet
def dataencode(account, amount, pin):
	return(dpd.dpdpack(account+'0'*(11-len(amount))+amount+pin))


def datadecode(input):
	data=dpd.dpdunpack(input)
	account=data[0:16]
	amount=data[16:27]
	pin=data[27:31]
	return([account, amount, pin])


def build_message(pubkey, ciphertext):
	data = chr(1) + chr(len(pubkey)) + pubkey + chr(len(ciphertext)) + ciphertext
	return(data)


def build_asn1(key):
	"""
	30 + 39 | 59 + \
	301306072a8648ce3d020106082a8648ce3d03010703
	22 | 42 + 00
	"""
	keylen = len(key)
	oids = binascii.a2b_hex("301306072a8648ce3d020106082a8648ce3d03010703")
	asn1 = chr(0x30) + chr(24+keylen) + oids + chr(1+keylen) + chr(0) + key
	return(asn1)


def parse_input(data):
	offset = 0
	version = ord(data[offset])
	offset = offset + 1
	keylen = ord(data[offset])
	offset = offset + 1
	key = data[offset:offset+keylen]
	offset = offset + keylen
	cryptlen = ord(data[offset])
	offset = offset + 1
	crypt = data[offset:offset+cryptlen]
	return(key, crypt)

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
	if ord(key[0]) == 2 or ord(key[0]) == 3:
		return(key)
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
