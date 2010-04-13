from M2Crypto import EC, EVP
import binascii, sys, cryptimage
debug=0

data = sys.stdin.read()
pubkey, ciphertext = cryptimage.parse_input(data)

if debug: sys.stderr.write("ct = %s\n" % binascii.b2a_hex(ciphertext))

ecpair = EC.load_key('eccpair.pem')

#if len(sys.argv[1]) < 150:
#asn1header = '3059301306072a8648ce3d020106082a8648ce3d030107034200'
asn1header = '3039301306072a8648ce3d020106082a8648ce3d030107032200'
#ephemeral = sys.argv[1][:130]
#data = sys.argv[1][130:]
#ephemeral = sys.argv[1][:66]
#data = sys.argv[1][66:]
ephemeral = EC.pub_key_from_der(binascii.a2b_hex(asn1header) + pubkey)

shared = ecpair.compute_dh_key(ephemeral.pub())

digest = EVP.MessageDigest("sha1")
ecder=ecpair.pub().get_der()
digest.update(ecder)
fingerprint = digest.digest()

dk=cryptimage.KDF(shared[:len(shared)/2],128,fingerprint)

cleartext = cryptimage.decrypt_data(dk,ciphertext)
print "decrypted text = %s" % cleartext

sys.exit(0)
