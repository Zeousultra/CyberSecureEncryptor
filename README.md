# 🔐 CyberSecureEncryptor

A simple yet powerful Python-based text encryption and decryption tool using three major encryption algorithms: **AES**, **DES**, and **RSA**. This tool provides an interactive command-line interface for secure data protection, ideal for learning and small-scale secure communication.

---

## 📌 Features

* 🔒 **AES Encryption** - Fast and secure symmetric encryption
* 🧩 **DES Encryption** - Legacy encryption algorithm for backward compatibility
* 🔑 **RSA Encryption** - Asymmetric encryption with public/private key pair
* 🔁 **Encryption & Decryption Options** - Full support for both directions
* 🔐 **Auto Key Generation** - For secure, random AES/DES keys
* 💬 **User-Friendly CLI Interface** - Clear and interactive prompts

---

## 🧪 How It Works

Upon running the script, you are prompted to choose between:

1. **Encryption**
2. **Decryption**

Depending on the choice, you select one of the following algorithms:

* AES
* DES
* RSA

The script will then:

* Prompt you for text input (for encryption) or ciphertext/key input (for decryption)
* Display the encrypted/decrypted result
* For AES/DES, it will generate and show a key you must save for decryption later

---

## 🚀 Getting Started

### 📥 Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/Zeousultra/CyberSecureEncryptor.git
   cd CyberSecureEncryptor
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

### ▶️ Run the tool:

```bash
python secure_encryptor.py
```

---

## 📦 Requirements

All dependencies are listed in `requirements.txt`. Main libraries used:

* `pycryptodome` - For AES and DES encryption
* `rsa` - For RSA key generation and encryption

---

## 🔐 Example Usage

### 🔸 AES Encryption Example:

```bash
Enter choice:
1. Encryption
2. Decryption
> 1

Select encryption method:
1. AES
2. DES
3. RSA
> 1
Enter your message:
Hello World!

[+] Encrypted Text: x7&...#k=
[+] AES Key (Save this!): b'\xa2...\x91'
```

### 🔸 AES Decryption Example:

```bash
Enter choice:
1. Encryption
2. Decryption
> 2

Select decryption method:
1. AES
2. DES
3. RSA
> 1
Enter encrypted text:
x7&...#k=
Enter AES Key:
b'\xa2...\x91'

[+] Decrypted Text: Hello World!
```

---

## 🧠 Educational Use Only

> This tool is built for **educational** and **learning** purposes only. Always use responsibly and ethically.

---

## 📁 Project Structure

```
CyberSecureEncryptor/
├── secure_encryptor.py           # Main encryption/decryption script
├── requirements.txt       # Dependencies
└── README.md              # Project documentation
```

---

## 👨‍💻 Author

**Athul M** — [LinkedIn](https://www.linkedin.com/in/athul-m-zeous/) | [GitHub](https://github.com/Zeousultra)

Feel free to ⭐ the repo if you found it useful!

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
