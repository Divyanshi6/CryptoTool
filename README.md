# 🔐 CryptoTool
# CryptoTool

CryptoTool is a Python-based desktop application developed using Tkinter that offers various encryption and decryption functionalities, such as Base64, Caesar Cipher, AES, RSA, and more. It allows users to encrypt, decrypt, and hash messages using different cryptographic algorithms. The application also features file handling, log management, and a dark/light theme toggle.

## Features

- **Multiple Cryptographic Algorithms**: Supports Base64, Caesar Cipher, Vigenère Cipher, AES, RSA, RC4, Atbash, and MD5 hashing.
- **File Handling**: Load and save encrypted/decrypted messages to/from files.
- **Log Management**: Keeps track of all encryption/decryption operations in a log.
- **Dark/Light Theme**: Toggle between dark and light modes for better user experience.
- **Error Handling**: Displays appropriate error messages for invalid inputs and operations.

## Requirements

- Python 3.x
- `pycryptodome` library (for AES and RSA encryption)
- `tkinter` (for GUI)

You can install the required dependencies using `pip`:

```bash
pip install pycryptodome
Usage
Select an Encryption Algorithm: Choose from algorithms such as Base64, Caesar Cipher, AES, RSA, and more.

Enter the Text and Key: Provide the message to be encrypted or decrypted along with the key (if applicable).

Select Mode: Choose the mode (Encrypt or Decrypt) using the radio buttons.

Generate Output: Click the "Process" button to encrypt or decrypt the text.

Save to File: Save the output to a file or load input from a file.

View Logs: View the history of encryption/decryption operations performed.

Supported Algorithms
Base64: Encodes/decodes data using the Base64 algorithm.

Caesar Cipher: A substitution cipher where each letter is shifted by a key.

Vigenère Cipher: A more advanced cipher that uses a key to shift each character.

AES (Advanced Encryption Standard): A symmetric block cipher with key sizes of 128, 192, or 256 bits.

RSA: Public-key cryptosystem for secure data transmission.

RC4: A stream cipher used for encrypting data byte-by-byte.

Atbash: A simple substitution cipher where each letter is replaced with its reverse counterpart.

MD5: A cryptographic hash function producing a 128-bit hash value.

Screenshots

How to Run
Clone this repository to your local machine:

bash
Copy
Edit
git clone https://github.com/your_username/CryptoTool.git
Navigate to the project directory:

bash
Copy
Edit
cd CryptoTool
Run the application:

bash
Copy
Edit
python main.py
Enjoy using CryptoTool!

Contributions
If you wish to contribute to this project, feel free to fork the repository and submit pull requests. Please ensure that your changes do not break existing functionality and that all code is properly documented.

License
This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgments
Thanks to the developers of pycryptodome for providing cryptographic algorithms.

Special thanks to Tkinter for the easy-to-use GUI framework.
