from M2Crypto import EVP
import struct, binascii

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
