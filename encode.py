from M2Crypto import EC, EVP
import binascii, sys, cryptimage
debug=0

asn1header = '3059301306072a8648ce3d020106082a8648ce3d030107034200'
epub = '04b6fd5e085b9aa66de4bb501d4ede5e2b5215680cc7d8c050aab7a8dc505213c107c42b04191bca6ae155f80803110a2d65b76acc0a234680a3ba165c60fef73e'
ecder = binascii.a2b_hex(asn1header + epub)

digest = EVP.MessageDigest("sha1")
digest.update(ecder)
fingerprint = digest.digest()
if debug: print "fingerprint = %s" % binascii.b2a_hex(fingerprint)

# NID_X9_62_prime256v1
ephemeral = EC.gen_params(EC.NID_X9_62_prime256v1)
ephemeral.gen_key()

ecpub = EC.pub_key_from_der(ecder)

shared = ephemeral.compute_dh_key(ecpub.pub())

print "ephemeral pub = %s" % binascii.b2a_hex(ephemeral.pub().get_der()[26:])
if debug: print "shared key = %s" % binascii.b2a_hex(shared)
dk=cryptimage.KDF(shared[:len(shared)/2],128,fingerprint)
if debug: print "derived key = %s" % binascii.b2a_hex(dk)

data="Hello World!"
enc=1
cipher = EVP.Cipher('aes_128_ecb', dk, '', enc)
cipher.update(data)
result = cipher.final()
print "encrypted text = %s" % binascii.b2a_hex(result)

sys.exit(0)
