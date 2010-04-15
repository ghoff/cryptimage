from M2Crypto import EC, EVP
import binascii, sys, cryptimage
debug=0

data = sys.stdin.read()
ephpub, ciphertext = cryptimage.parse_input(data)
ephemeral = EC.pub_key_from_der(cryptimage.build_asn1(ephpub))

if debug: sys.stderr.write("ct = %s\n" % binascii.b2a_hex(ciphertext))

ecpair = EC.load_key('eccpair.pem')
ecder = ecpair.pub().get_der()
ecpub = cryptimage.compress_key(cryptimage.strip_asn1(ecder))

digest = EVP.MessageDigest("sha1")
digest.update(ecpub)
fingerprint = digest.digest()

shared = ecpair.compute_dh_key(ephemeral.pub())

dk=cryptimage.KDF(shared[:len(shared)/2],128,fingerprint)

plaintext = cryptimage.decrypt_data(dk,ciphertext)
print "decrypted text = %s" % plaintext

sys.exit(0)
