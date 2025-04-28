# Quantum-Ready Cryptography Demo

## Overview
This project demonstrates a simple cryptographic system that is designed to be resistant to quantum computing attacks.

## Features
- **Post-Quantum Cryptography**: Implements Kyber512, a NIST-standardized algorithm for quantum-resistant key encapsulation.
- **Symmetric Encryption**: Uses AES-GCM for secure message encryption.
- **Secure Web Application**: Includes CSRF protection, secure session cookies, and HTTP security headers (e.g., HSTS, X-Content-Type-Options).
- **Responsive UI**: Built with Bootstrap, Font Awesome, and custom CSS for a polished, mobile-friendly interface.
- **Error Handling**: Provides clear error messages for invalid inputs, mismatched ciphertexts, and decryption failures.
- **Educational Purpose**: Displays keys and secrets for learning, with warnings about production use.
## Folder Structure
  quantum-crypto-demo/
│
├── static/
│   ├── css/
│   │   └── style.css           # Custom CSS for styling the frontend
│   └── js/
│       └── script.js           # Custom JavaScript (e.g., for copy-to-clipboard functionality)
│
├── templates/
│   └── index.html              # Main HTML template for the web interface
│
├── app.py                      # Main Flask application with routes and logic
├── README.md                   # This file
└── requirements.txt            # Python dependencies
