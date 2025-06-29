from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Generate keys
key = RSA.generate(2048)  # Creates a 2048-bit RSA key pair (256 bytes)
public_key = key.publickey().export_key()
private_key = key.export_key()
public_key_obj = RSA.import_key(public_key)

# Accept user message, hash message, then sign hash of message
input_message = str(input("Please enter a message to sign: "))
message = input_message.encode()
hash_obj = SHA256.new(message)  # Create hash object
signer_object = pkcs1_15.new(key)   #  Instantiate an object with the .sign method used to sign the key
signature = signer_object.sign(hash_obj)  # Sign the hash (hash_obj) with the private key-derived signer object

# Verifiy signature
verifier_object = pkcs1_15.new(public_key_obj)

try:
    verifier_object.verify(hash_obj, signature)
    print("Signature verification succeeded!")
except (ValueError, TypeError):
    print("Signature verification failed.")