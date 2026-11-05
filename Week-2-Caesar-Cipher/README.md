# Caesar Cipher Encryption & Decryption 🔐

## Project Overview

This project implements a basic encryption and decryption technique using the Caesar Cipher algorithm in Python.

The program allows users to enter a message and a custom shift key. It encrypts the message and then decrypts it to recover the original text.

## Features

- Encrypt user messages using Caesar Cipher.
- Decrypt encrypted messages.
- Custom shift key selection.
- Uppercase and lowercase letter handling.
- Preserves spaces, numbers and special characters.
- Handles alphabet wrapping using modulo 26.
- Validates shift key input.

## Technologies Used

- Python 3
- Visual Studio Code
- Git and GitHub

## How to Run

1. Open the project folder in VS Code.
2. Open the terminal.
3. Run the following command:

   `python caesar_cipher.py`

4. Enter your message.
5. Enter the shift key.
6. View the encrypted and decrypted messages.

## Example

**Input:**
- Message: Hello Anas!
- Shift Key: 3

**Encrypted Message:**
- Khoor Dqdv!

**Decrypted Message:**
- Hello Anas!

## Algorithm

Encryption:

`E(x) = (x + n) % 26`

Decryption:

`D(x) = (x - n) % 26`

Where:
- x = Character position in the alphabet.
- n = Shift key.
- 26 = Total number of English alphabet letters.

## Security Note

Caesar Cipher is a basic educational encryption technique. It is not suitable for protecting sensitive information in real-world applications.

## Internship Details

Cybersecurity Internship – DecodeLabs  
Project: 2  
Topic: Basic Encryption & Decryption