from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


def Diffie_Hellman():
    parameters = dh.generate_parameters(generator=2, key_size=1024)

    private_key_user1 = parameters.generate_private_key()
    public_key_user1 = private_key_user1.public_key()

    private_key_user2 = parameters.generate_private_key()
    public_key_user2 = private_key_user2.public_key()

    private_key_user3 = parameters.generate_private_key()
    public_key_user3 = private_key_user3.public_key()

    shared_key_user2 = private_key_user2.exchange(public_key_user1)

    shared_key_user1 = private_key_user1.exchange(public_key_user2)

    shared_key_attacker1 = private_key_user3.exchange(public_key_user1)

    shared_key_attacker2 = private_key_user3.exchange(public_key_user2)

    derived_key_user1 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key_user1)

    derived_key_user2 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key_user2)

    derived_key_attacker1 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key_attacker1)

    derived_key_attacker2 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key_attacker2)

    return (
        public_key_user1.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo),
        derived_key_user1,
        public_key_user2.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo),
        derived_key_user2,
        derived_key_attacker1,
        derived_key_attacker2
    )


def encrypt_message(key, message):
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv, ciphertext


def decrypt_message(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    try:
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    except ValueError:
        return decrypted_data

    return unpadded_data


def man_in_the_middle_attack(encrypted_message, derived_key_attacker1, derived_key_attacker2):
    iv, ciphertext = encrypted_message

    decrypted_message = decrypt_message(derived_key_attacker1, iv, ciphertext)

    reencrypted_message = encrypt_message(derived_key_attacker2, decrypted_message)

    return decrypted_message, reencrypted_message


public_key_user1, derived_key_user1, public_key_user2, derived_key_user2, derived_key_attacker1, derived_key_attacker2 = Diffie_Hellman()

message = b"Secret message from Alice to Bob"
iv, ciphertext = encrypt_message(derived_key_user1, message)
encrypted_message = (iv, ciphertext)

eavesdropped_message, sent_message = man_in_the_middle_attack(encrypted_message, derived_key_user1,
                                                              derived_key_attacker2)
iv, ciphertext = sent_message
decrypted_message = decrypt_message(derived_key_attacker2, iv, ciphertext)

print("Original Message from Alice to Bob:", message)
print("Eavesdropped message read by the attacker:", eavesdropped_message)
print("Message received by Bob from the attacker:", decrypted_message)
