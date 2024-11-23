import random
import string
import hashlib
import time

# Generate 100 random messages with at least 100 characters each
def generate_random_messages(num_messages=1000, min_length=10**6):
    messages = []
    for _ in range(num_messages):
        message = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=min_length))
        messages.append(message)
    return messages

# Hash a message with MD5
def hash_md5(message):
    return hashlib.md5(message.encode()).hexdigest()

# Hash a message with SHA-256
def hash_sha256(message):
    return hashlib.sha256(message.encode()).hexdigest()

# Compare MD5 and SHA-256 hashing performance
def compare_hashing_algorithms(messages):
    results = {"md5": [], "sha256": []}

    # Measure time for MD5
    start = time.time()
    for msg in messages:
        hash_md5(msg)
    results["md5"].append(time.time() - start)

    # Measure time for SHA-256
    start = time.time()
    for msg in messages:
        hash_sha256(msg)
    results["sha256"].append(time.time() - start)

    return results

# Main logic
if __name__ == "__main__":
    messages = generate_random_messages()

    # Hash messages and compare
    results = compare_hashing_algorithms(messages)

    print("Performance (time taken to hash 1000 messages):")
    print(f"MD5: {results['md5'][0]} seconds")
    print(f"SHA-256: {results['sha256'][0]} seconds")

    # Hash examples
    example_message = messages[0]
    print("\nExample hashes:")
    print(f"Original message: {example_message}")
    print(f"MD5 hash: {hash_md5(example_message)}")
    print(f"SHA-256 hash: {hash_sha256(example_message)}")
