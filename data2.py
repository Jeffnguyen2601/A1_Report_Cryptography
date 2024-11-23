import os
import random
import time
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# Generate 100 random messages
def generate_random_messages(num_messages=100, min_length=100):
    messages = []
    for _ in range(num_messages):
        message = ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ", k=random.randint(min_length, min_length + 50)))
        messages.append(message)
    return messages

# AES Encryption/Decryption with time tracking
def aes_encrypt_decrypt(message):
    key = get_random_bytes(16)  # AES key size of 128 bits
    cipher = AES.new(key, AES.MODE_EAX)
    start_encrypt = time.time()
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    end_encrypt = time.time()

    start_decrypt = time.time()
    decipher = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
    decrypted_message = decipher.decrypt(ciphertext).decode()
    end_decrypt = time.time()

    return ciphertext, decrypted_message, (end_encrypt - start_encrypt) * 1000, (end_decrypt - start_decrypt) * 1000

# DES Encryption/Decryption with time tracking
def des_encrypt_decrypt(message):
    key = get_random_bytes(8)  # DES key size of 56 bits
    cipher = DES.new(key, DES.MODE_EAX)
    start_encrypt = time.time()
    ciphertext = cipher.encrypt(message.encode().ljust(8))  # Pad to 8 bytes
    end_encrypt = time.time()

    start_decrypt = time.time()
    decipher = DES.new(key, DES.MODE_EAX, nonce=cipher.nonce)
    decrypted_message = decipher.decrypt(ciphertext).decode().strip()
    end_decrypt = time.time()

    return ciphertext, decrypted_message, (end_encrypt - start_encrypt) * 1000, (end_decrypt - start_decrypt) * 1000

# 3DES Encryption/Decryption with time tracking
def des3_encrypt_decrypt(message):
    key = get_random_bytes(24)  # 3DES key size of 168 bits
    cipher = DES3.new(key, DES3.MODE_EAX)
    start_encrypt = time.time()
    ciphertext = cipher.encrypt(message.encode().ljust(8))  # Pad to 8 bytes
    end_encrypt = time.time()

    start_decrypt = time.time()
    decipher = DES3.new(key, DES3.MODE_EAX, nonce=cipher.nonce)
    decrypted_message = decipher.decrypt(ciphertext).decode().strip()
    end_decrypt = time.time()

    return ciphertext, decrypted_message, (end_encrypt - start_encrypt) * 1000, (end_decrypt - start_decrypt) * 1000

# Main Execution
def main():
    # Generate 100 random messages
    messages = generate_random_messages()
    print("Generated Messages: ", len(messages))
    
    aes_times = {"encrypt": [], "decrypt": []}
    des_times = {"encrypt": [], "decrypt": []}
    des3_times = {"encrypt": [], "decrypt": []}
    
    for message in messages:
        # AES Encryption/Decryption
        aes_encrypted, aes_decrypted, aes_enc_time, aes_dec_time = aes_encrypt_decrypt(message)
        aes_times["encrypt"].append(aes_enc_time)
        aes_times["decrypt"].append(aes_dec_time)
        
        # DES Encryption/Decryption
        des_encrypted, des_decrypted, des_enc_time, des_dec_time = des_encrypt_decrypt(message)
        des_times["encrypt"].append(des_enc_time)
        des_times["decrypt"].append(des_dec_time)

        # 3DES Encryption/Decryption
        des3_encrypted, des3_decrypted, des3_enc_time, des3_dec_time = des3_encrypt_decrypt(message)
        des3_times["encrypt"].append(des3_enc_time)
        des3_times["decrypt"].append(des3_dec_time)
    
    # Display individual times
    print("\n=== Encryption and Decryption Times for Each Method ===")
    for i, message in enumerate(messages):
        print(f"Message {i+1}:")
        print(f"  AES -> Encrypt: {aes_times['encrypt'][i]:.2f}ms, Decrypt: {aes_times['decrypt'][i]:.2f}ms")
        print(f"  DES -> Encrypt: {des_times['encrypt'][i]:.2f}ms, Decrypt: {des_times['decrypt'][i]:.2f}ms")
        print(f"  3DES -> Encrypt: {des3_times['encrypt'][i]:.2f}ms, Decrypt: {des3_times['decrypt'][i]:.2f}ms")

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

    analyze_times(aes_times["encrypt"], "AES", "Encryption")
    analyze_times(aes_times["decrypt"], "AES", "Decryption")
    analyze_times(des_times["encrypt"], "DES", "Encryption")
    analyze_times(des_times["decrypt"], "DES", "Decryption")
    analyze_times(des3_times["encrypt"], "3DES", "Encryption")
    analyze_times(des3_times["decrypt"], "3DES", "Decryption")

if __name__ == "__main__":
    main()
