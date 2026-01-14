import os
from flask import Flask, request, render_template, send_file
from werkzeug.utils import secure_filename
import io

# Import our custom crypto tool
from crypto_utils import encrypt_data, decrypt_data

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    password = request.form.get('password')

    if file.filename == '' or not password:
        return 'File and Password are required!', 400

    if file:
        filename = secure_filename(file.filename)
        
        # 1. Read the raw bytes from the uploaded file
        file_bytes = file.read()
        
        # 2. Encrypt the data
        # We get back the 4 crucial pieces
        salt, nonce, tag, ciphertext = encrypt_data(file_bytes, password)
        
        # 3. Pack everything into ONE file
        # Structure: [SALT (16)] + [NONCE (16)] + [TAG (16)] + [CIPHERTEXT]
        final_data = salt + nonce + tag + ciphertext
        
        # 4. Save the encrypted file
        # We add .enc to distinguish it
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + ".enc")
        
        with open(save_path, "wb") as f:
            f.write(final_data)
        
        return f"File '{filename}' encrypted and saved as '{filename}.enc'!"
    
@app.route('/download', methods=['POST'])
def download_file():
    # In a real app, you'd ask for the filename. 
    # For this Sprint, we'll hardcode or ask the user to type the filename to decrypt.
    filename = request.form.get('filename') # User types "image.jpg"
    password = request.form.get('password')
    
    # We look for the .enc version
    encrypted_filename = secure_filename(filename) + ".enc"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
    
    if not os.path.exists(file_path):
        return "File not found!", 404
        
    # 1. Read the encrypted file
    with open(file_path, "rb") as f:
        file_content = f.read()
        
    # 2. Slice the Data (Unpacking the Sandwich)
    # We know exact sizes from crypto_utils.py
    salt = file_content[:16]   # First 16 bytes
    nonce = file_content[16:32] # Next 16 bytes
    tag = file_content[32:48]   # Next 16 bytes
    ciphertext = file_content[48:] # The rest
    
    # 3. Decrypt
    decrypted_data = decrypt_data(salt, nonce, tag, ciphertext, password)
    
    if decrypted_data is None:
        return "Wrong Password or Corrupt File!", 403
        
    # 4. Send back to browser
    # We use io.BytesIO to treat the raw bytes like a file object
    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=filename # The original name (image.jpg)
    )

if __name__ == '__main__':
    app.run(debug=True)