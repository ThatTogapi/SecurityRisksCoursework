from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def hash_message(message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    return digest.finalize()


def sign_message(private_key, message):
    hashed_message = hash_message(message)
    signature = private_key.sign(
        hashed_message,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    return signature


def verify_signature(public_key, message, signature):
    hashed_message = hash_message(message)
    try:
        public_key.verify(
            signature,
            hashed_message,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        return True
    except Exception as e:
        return False


if __name__ == "__main__":
    private_key, public_key = generate_key_pair()
    print("Private Key:", private_key)
    print("Public Key:", public_key)

    message = input("Enter the message to sign: ")

    signature = sign_message(private_key, message)
    print("Signature:", signature)

    is_valid = verify_signature(public_key, message, signature)
    print("Signature Verification Result:", is_valid)
