# AES-Tools 
(AES Image Encryptor/Decryptor)

A tool for encrypting and decrypting images using AES encryption.

# Overview

This project is a simple tool for encrypting and decrypting images using the Advanced Encryption Standard (AES). It leverages the PBKDF2 key derivation function to securely derive encryption keys from user-provided passwords. The application features a user-friendly graphical interface built with Tkinter.

# Features

- **Image Encryption**: Securely encrypt images using a password.
- **Image Decryption**: Decrypt previously encrypted images using the same password.
- **Random Salt**: Uses a random salt for each encryption to enhance security.
- **Initialization Vector (IV)**: Generates a unique IV for each encryption operation.
- **User Interface**: Easy-to-use GUI for selecting images, entering passwords, and saving encrypted or decrypted images.

# Requirements

To run this project, you need to have Python installed along with the following libraries:

- cryptography
- tkinter 

You can install the necessary library with pip:

- pip install cryptography
- pip install tk
