# SecureShare: Zero-Knowledge File Transfer System

**SecureShare** is a secure file sharing application built with Python and Flask. It implements a **Zero-Knowledge Architecture**, ensuring that the server never stores plain-text files or encryption keys. All data is encrypted using industry-standard AES-256-GCM before being saved to the disk.

## 🚀 Key Features

* **Zero-Knowledge Privacy:** The server administrator cannot view user files. Decryption keys are derived transiently from user passwords and never stored.
* **AES-256-GCM Encryption:** Uses Galois/Counter Mode (GCM) to provide both confidentiality and data integrity (tamper detection).
* **Robust Key Derivation:** Implements **PBKDF2** (SHA-256) with 100,000 iterations and unique salts to prevent rainbow table and brute-force attacks.
* **Secure File Structure:** Custom binary file packaging that embeds cryptographic artifacts (Salt, Nonce, Tag) directly into the encrypted file.

## 🛠️ Tech Stack

* **Backend:** Python 3, Flask
* **Cryptography:** PyCryptodome
* **Frontend:** HTML5, CSS3 (Basic Interface)

## ⚙️ Installation & Setup

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/yourusername/secure-share.git](https://github.com/yourusername/secure-share.git)
    cd secure-share
    ```

2.  **Create a Virtual Environment**
    ```bash
    # Windows
    python -m venv venv
    venv\Scripts\activate

    # Mac/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install flask pycryptodome
    ```

4.  **Run the Application**
    ```bash
    python app.py
    ```
    The server will start at `http://127.0.0.1:5000/`.

## 📖 How to Use

### 1. Uploading a File
1.  Navigate to the homepage.
2.  Select a file to upload.
3.  Enter a strong **Password**.
4.  Click **Secure Upload**.
    * *Behind the scenes:* The app generates a random Salt, derives a Key, encrypts the file, and saves it as `filename.ext.enc`.

### 2. Downloading a File
1.  Enter the original filename (e.g., `image.png`).
2.  Enter the **same Password** used during upload.
3.  Click **Decrypt & Download**.
    * *Behind the scenes:* The app reads the Salt from the file header, re-derives the Key, verifies the Integrity Tag, and serves the decrypted file.

## 🔐 Security Architecture

### The Encryption Process
Unlike standard uploads, SecureShare modifies the file binary structure. The final saved file on the disk follows this byte-level layout:

```text
[ 16 Bytes (Salt) ] + [ 16 Bytes (Nonce) ] + [ 16 Bytes (Tag) ] + [ Encrypted Data... ]