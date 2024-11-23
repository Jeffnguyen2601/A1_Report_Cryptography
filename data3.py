import os
import random
import time
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256

# Generate 100 random messages
def generate_random_messages(num_messages=100, min_length=100):
    messages = []
    for _ in range(num_messages):
        message = ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ", k=random.randint(min_length, min_length + 50)))
        messages.append(message)
    return messages

# RSA Encryption/Decryption with time tracking
def rsa_encrypt_decrypt(message):
    # Generate RSA keys
    key = RSA.generate(2048)
    public_key = key.publickey()

    # Record key size
    rsa_key_size = key.size_in_bits()

    # Encrypt message
    start_encrypt = time.time()
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message.encode())
    end_encrypt = time.time()

    # Decrypt message
    start_decrypt = time.time()
    decipher = PKCS1_OAEP.new(key)
    decrypted = decipher.decrypt(encrypted).decode()
    end_decrypt = time.time()

    return encrypted, decrypted, rsa_key_size, (end_encrypt - start_encrypt) * 1000, (end_decrypt - start_decrypt) * 1000

# ECC Encryption/Decryption with time tracking
def ecc_encrypt_decrypt(message):
    # Generate ECC key pair
    key = ECC.generate(curve='P-256')
    public_key = key.public_key()

    # Record key size
    ecc_key_size = key.pointQ.size_in_bytes() * 8  # Convert to bits

    # Generate shared secret
    shared_secret = key.pointQ * key.d  # Elliptic curve point multiplication
    shared_secret_bytes = shared_secret.x.to_bytes(32, byteorder='big')  # Convert x-coordinate to bytes

    # Derive AES key from shared secret
    hash_obj = SHA256.new(shared_secret_bytes)
    aes_key = hash_obj.digest()[:16]  # Use first 16 bytes for AES key

    # Encrypt message
    start_encrypt = time.time()
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    end_encrypt = time.time()

    # Decrypt message
    start_decrypt = time.time()
    decipher = AES.new(aes_key, AES.MODE_EAX, nonce=cipher.nonce)
    decrypted_message = decipher.decrypt(ciphertext).decode()
    end_decrypt = time.time()

    return ciphertext, decrypted_message, ecc_key_size, (end_encrypt - start_encrypt) * 1000, (end_decrypt - start_decrypt) * 1000

# Main Execution
def main():
    # Generate 100 random messages
    messages = generate_random_messages()
    print("Generated Messages: ", len(messages))
    
    rsa_times = {"encrypt": [], "decrypt": []}
    ecc_times = {"encrypt": [], "decrypt": []}
    key_sizes = {"rsa": [], "ecc": []}
    
    for message in messages:
        # RSA Encryption/Decryption
        rsa_encrypted, rsa_decrypted, rsa_key_size, rsa_enc_time, rsa_dec_time = rsa_encrypt_decrypt(message)
        rsa_times["encrypt"].append(rsa_enc_time)
        rsa_times["decrypt"].append(rsa_dec_time)
        key_sizes["rsa"].append(rsa_key_size)
        
        # ECC Encryption/Decryption
        ecc_encrypted, ecc_decrypted, ecc_key_size, ecc_enc_time, ecc_dec_time = ecc_encrypt_decrypt(message)
        ecc_times["encrypt"].append(ecc_enc_time)
        ecc_times["decrypt"].append(ecc_dec_time)
        key_sizes["ecc"].append(ecc_key_size)
    
    # Display individual times and key sizes
    print("\n=== Encryption and Decryption Times for Each Method ===")
    for i, message in enumerate(messages):
        print(f"Message {i+1}:")
        print(f"  RSA -> Key Size: {key_sizes['rsa'][i]} bits, Encrypt: {rsa_times['encrypt'][i]:.2f}ms, Decrypt: {rsa_times['decrypt'][i]:.2f}ms")
        print(f"  ECC -> Key Size: {key_sizes['ecc'][i]} bits, Encrypt: {ecc_times['encrypt'][i]:.2f}ms, Decrypt: {ecc_times['decrypt'][i]:.2f}ms")

    # Statistical Analysis
    print("\n=== Statistical Analysis ===")
    def analyze_times(times, method, operation):
        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)
        print(f"{method} {operation}:")
        print(f"  Average: {avg_time:.2f}ms")
        print(f"  Fastest: {min_time:.2f}ms")
        print(f"  Slowest: {max_time:.2f}ms")

    def analyze_key_sizes(sizes, method):
        avg_size = sum(sizes) / len(sizes)
        print(f"{method} Key Sizes:")
        print(f"  Average: {avg_size:.2f} bits")
        print(f"  Example: {sizes[0]} bits (Message 1)")

    analyze_times(rsa_times["encrypt"], "RSA", "Encryption")
    analyze_times(rsa_times["decrypt"], "RSA", "Decryption")
    analyze_times(ecc_times["encrypt"], "ECC", "Encryption")
    analyze_times(ecc_times["decrypt"], "ECC", "Decryption")
    analyze_key_sizes(key_sizes["rsa"], "RSA")
    analyze_key_sizes(key_sizes["ecc"], "ECC")

if __name__ == "__main__":
    main()
