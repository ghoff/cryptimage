from M2Crypto import EC, EVP
import binascii, sys, cryptimage
debug=0

asn1header = '3059301306072a8648ce3d020106082a8648ce3d030107034200'
epub = '04b6fd5e085b9aa66de4bb501d4ede5e2b5215680cc7d8c050aab7a8dc505213c107c42b04191bca6ae155f80803110a2d65b76acc0a234680a3ba165c60fef73e'
ecder = binascii.a2b_hex(asn1header + epub)

#asn1headercomp = '3039301306072a8648ce3d020106082a8648ce3d030107032200'
#ecpubcomp = '02b6fd5e085b9aa66de4bb501d4ede5e2b5215680cc7d8c050aab7a8dc505213c1'
#ecder = binascii.a2b_hex(asn1headercomp + ecpubcomp)
ecpub = EC.pub_key_from_der(ecder)

digest = EVP.MessageDigest("sha1")
digest.update(ecder)
fingerprint = digest.digest()

# NID_X9_62_prime256v1
ephemeral = EC.gen_params(EC.NID_X9_62_prime256v1)
ephemeral.gen_key()

shared = ephemeral.compute_dh_key(ecpub.pub())

ephpub=cryptimage.strip_asn1(ephemeral.pub().get_der())
ephpub=cryptimage.compress_key(ephpub)

#strip second half of key which is y cordinates and can be derived from first half
dk=cryptimage.KDF(shared[:len(shared)/2],128,fingerprint)

if debug: sys.stderr.write("dk = %s\n" % binascii.b2a_hex(dk))

data="Hello World!"
ct = cryptimage.encrypt_data(dk,data)

sys.stdout.write(chr(1) + chr(len(ephpub)) + ephpub + chr(len(ct)) + ct)

sys.exit(0)
