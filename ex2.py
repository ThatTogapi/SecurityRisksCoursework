from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def Diffie_Hellman():
    parameters = dh.generate_parameters(generator=2, key_size=1024)

    private_key_user1 = parameters.generate_private_key()

    public_key_user1 = private_key_user1.public_key()

    private_key_user2 = parameters.generate_private_key()

    public_key_user2 = private_key_user2.public_key()

    private_key_user3 = parameters.generate_private_key()

    shared_key_user2 = private_key_user2.exchange(public_key_user1)

    shared_key_user1 = private_key_user1.exchange(public_key_user2)

    shared_key_attacker1 = private_key_user3.exchange(public_key_user1)

    shared_key_attacker2 = private_key_user3.exchange(public_key_user2)

    derived_key_user1 = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(
        shared_key_user1)

    derived_key_user2 = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(
        shared_key_user2)

    derived_key_attacker1 = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(
        shared_key_attacker1)

    derived_key_attacker2 = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(
        shared_key_attacker2)

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


public_key_user1, derived_key_user1, public_key_user2, derived_key_user2, derived_key_attacker1, derived_key_attacker2 = Diffie_Hellman()

print("User1's Public Key (PEM format):")
print(public_key_user1.decode())

print("\nUser1's Derived Key:")
print(derived_key_user1)

print("\nUser2's Public Key (PEM format):")
print(public_key_user2.decode())

print("\nUser2's Derived Key:")
print(derived_key_user2)

print("\nAttacker's Derived Key with User1:")
print(derived_key_attacker1)

print("\nAttacker's Derived Key with User2:")
print(derived_key_attacker2)
