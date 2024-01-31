import hashlib

text = "123"
def text_to_sha256(text):
    # Encode the text as bytes and calculate the SHA-256 hash
    sha256_hash = hashlib.sha256(text.encode()).hexdigest()
    return sha256_hash

def sha256_to_binary(input_hash):
    # Convert the hexadecimal hash to bytes
    hash_bytes = bytes.fromhex(input_hash)

    # Convert bytes to binary representation
    binary_representation = ''.join(format(byte, '08b') for byte in hash_bytes)

    return binary_representation


def binary_string_to_sha256(binary_string):
    # Convert binary string to bytes
    binary_bytes = int(binary_string, 2).to_bytes((len(binary_string) + 7) // 8, byteorder='big')

    # Calculate the SHA-256 hash
    sha256_hash = hashlib.sha256(binary_bytes).hexdigest()
    return sha256_hash

# Example usage:
sha256_hash = text_to_sha256(text)
binary_result = sha256_to_binary(sha256_hash)
newSha = binary_string_to_sha256(binary_result)

print("SHA-256 Hash:", sha256_hash)
print("Binary Representation:", binary_result)
print("New Hash:", newSha)
