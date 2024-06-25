from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
from base64 import b64decode

def decrypt_aes_gcm(ciphertext, key, nonce, add):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(add)
    plaintext = cipher.decrypt(ciphertext)
    
    return plaintext

def main():
    key = bytes.fromhex("82122217ab0b5e6234c6a5e708668776")  # 16 bytes AES key
    nonce = bytes.fromhex("005d6af90000000000000001")          # 12 bytes nonce
    ciphertext = bytes.fromhex("7631873987af8aa45ce22ba694cafe5fab4443660ec0b9d206b60d86994d9ca8ffb0c5f13ae720f902bd734c85e7c5405e9824de5fadacf0635eeaa1283608abc56b806b233e")  # Encrypted text
    add = bytes.fromhex("000000000000011703030046")            # Additional authenticated data

    decryptedtext = decrypt_aes_gcm(ciphertext, key, nonce, add)

    print(f"Decrypted text is:{decryptedtext}")
    

if __name__ == "__main__":
    main()
