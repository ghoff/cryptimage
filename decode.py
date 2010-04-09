from M2Crypto import EC, EVP
import binascii, sys, cryptimage
debug=0

ecpair = EC.load_key('eccpair.pem')

asn1header = '3059301306072a8648ce3d020106082a8648ce3d030107034200'
ephemeral = sys.argv[1][:130]
data = sys.argv[1][130:]
ephemeral = EC.pub_key_from_der(binascii.a2b_hex(asn1header + ephemeral))

shared = ecpair.compute_dh_key(ephemeral.pub())

digest = EVP.MessageDigest("sha1")
digest.update(ecpair.pub().get_der())
fingerprint = digest.digest()

if debug: print "shared key = %s" % binascii.b2a_hex(shared)
dk=cryptimage.KDF(shared[:len(shared)/2],128,fingerprint)
if debug: print "derived key = %s" % binascii.b2a_hex(dk)

dec=0
cipher = EVP.Cipher('aes_128_ecb', dk, '', dec)
cipher.update(binascii.a2b_hex(data))
result = cipher.final()
print "decrypted text = %s" % result

sys.exit(0)
