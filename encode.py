from M2Crypto import EC, EVP
import binascii, sys, cryptimage
from pydmtx import DataMatrix
debug=0

ecpubkey = binascii.a2b_hex('02b6fd5e085b9aa66de4bb501d4ede5e2b5215680cc7d8c050aab7a8dc505213c1')
ecder = cryptimage.build_asn1(ecpubkey)
ecpub = EC.pub_key_from_der(ecder)

digest = EVP.MessageDigest("sha1")
digest.update(cryptimage.compress_key(ecpubkey))
fingerprint = digest.digest()

# NID_X9_62_prime256v1
ephemeral = EC.gen_params(EC.NID_X9_62_prime256v1)
ephemeral.gen_key()
ephpub=cryptimage.strip_asn1(ephemeral.pub().get_der())
ephpub=cryptimage.compress_key(ephpub)

shared = ephemeral.compute_dh_key(ecpub.pub())

#strip second half of key which is y cordinates and can be derived from first half
dk=cryptimage.KDF(shared[:len(shared)/2],128,fingerprint)

if debug: sys.stderr.write("dk = %s\n" % binascii.b2a_hex(dk))

account="2000111122223333"
amount="1500050"
pin="7654"

data=cryptimage.dataencode(account,amount,pin)
ct = cryptimage.encrypt_data(dk,data)

message = cryptimage.build_message(ephpub, ct)

dm_write = DataMatrix(scheme=DataMatrix.DmtxSchemeBase256)
dm_write.encode(message)
dm_write.save("dm.png", "png")

sys.exit(0)
