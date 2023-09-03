# AES-GCM Encryption and Decryption

This repository contains a Python script for encrypting and decrypting data using the AES-GCM algorithm.
I have written this, to test a Snowflake external function for encrypt and decrypt a column.

## Code Overview

The script contains three main functions:

1. `encrypt_data(data: str, key: bytes, iv: str, aad: str) -> str`: This function encrypts the given data using AES-GCM algorithm and returns the encrypted data in hexadecimal format.

2. `decrypt_data(encrypted_hex: str, key: bytes, iv: str, aad: str) -> str`: This function decrypts the given encrypted data in hexadecimal format and returns the decrypted data as string.

3. `process_data(request)`: This function processes a request to encrypt or decrypt data. The request should be a dictionary with a 'data' key containing a list of items to be processed. Each item should be a list containing an id, the data to be processed, and the operation ('encrypt' or 'decrypt').

## Usage

Here is an example of how to use the script:

```python
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
```

## Result

The result will look like this.

```python
[[0, "a620902ccdabceb5bbce0ecd82332531dc2320158954e93aaf134d306f0e6ced3226e244"], [1, "a620902ccdabceb5bbce0ecd8233252ac5292016cd2fe786bd2fffa802133b7e981e9da4"]]
[[0, "Test_data_text one 1"], [1, "Test_data_text two 2"]]
```
