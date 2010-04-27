This is a proof of concept out of band verification using hybrid elliptic curve key agreement aes
encryption and data matrix image encoding.  It requires OpenSSL with ECC (not provided in Fedora),
the Python module M2Crypto, libdmtx and the python wrapper from version 0.7.2.

encode.py takes no input and outputs the image file dm.png
decode.py take dm.png as input and outputs results of decrypted message:

Destination account number is: 2000111122223333
Amount to be transfered: 15000.50
Please enter pin 7654 to verify transaction

