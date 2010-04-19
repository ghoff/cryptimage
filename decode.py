from M2Crypto import EC, EVP, BIO
import binascii, sys, cryptimage
from pydmtx import DataMatrix
from PIL import Image
debug=0

dm_read = DataMatrix(scheme=DataMatrix.DmtxSchemeBase256)
img = Image.open("dm.png")
data = dm_read.decode(img.size[0],img.size[1],img.tostring())
#print data
#sys.exit(0)

#data = sys.stdin.read()
ephpub, ciphertext = cryptimage.parse_input(data)
ephemeral = EC.pub_key_from_der(cryptimage.build_asn1(ephpub))

if debug: sys.stderr.write("ct = %s\n" % binascii.b2a_hex(ciphertext))

ecpairpem = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIH8TNBOfV+JWVBr25KfjJ1007paZ/JnrvjxFzZThUgSToAoGCCqGSM49
AwEHoUQDQgAEtv1eCFuapm3ku1AdTt5eK1IVaAzH2MBQqreo3FBSE8EHxCsEGRvK
auFV+AgDEQotZbdqzAojRoCjuhZcYP73Pg==
-----END EC PRIVATE KEY-----
"""

ecbio = BIO.MemoryBuffer()
ecbio.write(ecpairpem)
ecpair = EC.load_key_bio(ecbio)
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
