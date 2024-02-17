import numpy as np

def decrypt(cipher_text, key_matrix, num_X, modulus=26):
    plain_text = ""
    for i in range(0, len(cipher_text), len(key_matrix)):
        block = ''

        for char in cipher_text[i:i + len(key_matrix)]:
            if char.isupper():
                block += char

        if len(block) < len(key_matrix):
            continue

        block_vector = np.array([ord(char) - ord('A') for char in block])

        det = int(np.round(np.linalg.det(key_matrix))) % modulus
        det_inv = pow(det, -1, modulus)

        adj = np.array([[key_matrix[1, 1], -key_matrix[0, 1]], [-key_matrix[1, 0], key_matrix[0, 0]]])
        inv_matrix = (det_inv * adj) % modulus

        decrypted_vector = np.dot(inv_matrix, block_vector) % modulus
        decrypted_vector = np.round(decrypted_vector).astype(int)

        for index, char in enumerate(block):
            plain_text += chr(decrypted_vector[index] + ord('A'))

    plain_text = plain_text[:len(plain_text)-num_X]
    return plain_text

def encrypt(plain_text, key_matrix, modulus=26):
    num_X = 0

    if len(plain_text) % len(key_matrix) != 0:
        num_X = len(key_matrix) - len(plain_text) % len(key_matrix)
        plain_text += 'X' * num_X

    cipher_text = ""

    for i in range(0, len(plain_text), len(key_matrix)):

        block = plain_text[i:i + len(key_matrix)]
        block_vector = np.array([ord(char) - ord('A') for char in block])
        encrypted_vector = np.dot(key_matrix, block_vector) % modulus

        for index, char in enumerate(block):
            cipher_text += chr(int(encrypted_vector[index]) + ord('A'))
            
    return cipher_text, num_X

if __name__ == "__main__":
    while True:
        plain_text = input("Enter plaintext IN CAPITAL LETTERS only (type 'exit' to quit): ")
        if plain_text.lower() == 'exit':
            break
        key_matrix = np.array([[1, 3], [2, 3]])
        cipher_text, num_X = encrypt(plain_text, key_matrix)
        decrypted_text = decrypt(cipher_text, key_matrix, num_X)
        print("Ciphertext:", cipher_text)
        print("Decrypted plaintext:", decrypted_text)
