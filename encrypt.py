import json
import hashlib
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_data(data: str, key: bytes, iv: str, aad: str) -> str:
    """
    Encrypts the given data using AES-GCM algorithm and returns the encrypted data in hexadecimal format.
    
    :param data: The data to be encrypted.
    :param key: The encryption key.
    :param iv: The initialization vector.
    :param aad: The additional authenticated data.
    :return: The encrypted data in hexadecimal format or an error message if the encryption fails.
    """
    try:
        # Create an AESGCM object with the given key
        aesgcm = AESGCM(key)
        # Encrypt the data using the AESGCM object, initialization vector, and additional authenticated data
        encrypted_data = aesgcm.encrypt(iv.encode(), data.encode(), aad.encode())
        # Convert the encrypted data to hexadecimal format
        encrypted_hex = binascii.hexlify(encrypted_data).decode()
        return encrypted_hex
    except Exception as e:
        return f'Error: {str(e)}'


def decrypt_data(encrypted_hex: str, key: bytes, iv: str, aad: str) -> str:
    """
    Decrypts the given encrypted data in hexadecimal format and returns the decrypted data as string.
    
    :param encrypted_hex: The encrypted data in hexadecimal format to be decrypted.
    :param key: The decryption key.
    :param iv: The initialization vector.
    :param aad: The additional authenticated data.
    :return: The decrypted data as string or an error message if the decryption fails.
    """
    try:
        # Convert the encrypted data from hexadecimal format to binary
        encrypted_data = binascii.unhexlify(encrypted_hex)
        # Create an AESGCM object with the given key
        aesgcm = AESGCM(key)
        # Decrypt the data using the AESGCM object, initialization vector, and additional authenticated data
        decrypted_data = aesgcm.decrypt(iv.encode(), encrypted_data, aad.encode())
        return decrypted_data.decode()
    except Exception as e:
        return f'Error: {str(e)}'


def process_data(request):

    password = 'Passwort12311111111111111111111111111111111145678'
    iv = 'IVSuperpasswort'
    aad = 'AADSuperpasswort'

    # Parse the JSON request
    # data = json.loads(request)
    data = request

    # Extract the relevant information from the JSON object
    data_list = data['data']
    
    # Hashing the password to use as encryption/decryption key
    password_hash = hashlib.sha256(password.encode()).digest()
    
    result = []
    
    for item in data_list:
        id = item[0]
        data_str = item[1]
        operation = item[2]
        
        try:
            if operation == 'encrypt':
                # Encrypt the data using the encrypt_data function
                finished_data = encrypt_data(data_str, password_hash, iv, aad)
                result.append([id, finished_data])
            elif operation == 'decrypt':
                # Decrypt the data using the decrypt_data function
                finished_data = decrypt_data(data_str, password_hash, iv, aad)
                result.append([id, finished_data])
            else:
                result.append([id, 'Error'])
        except:
            result.append([id, 'Error'])
    
    return json.dumps(result)

     
encrypted_data = process_data({
    "data": [
                [0, "Test_data_text one 1", "encrypt"],
                [1, "Test_data_text two 2", "encrypt"]
            ]
})

print(encrypted_data)

decrypted_data = process_data({
    "data": [
                [0, "a620902ccdabceb5bbce0ecd82332531dc2320158954e93aaf134d306f0e6ced3226e244", "decrypt"],
                [1, "a620902ccdabceb5bbce0ecd8233252ac5292016cd2fe786bd2fffa802133b7e981e9da4", "decrypt"]
            ]
})

print(decrypted_data)