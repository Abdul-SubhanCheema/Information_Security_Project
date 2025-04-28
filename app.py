from flask import Flask, render_template, request, session, redirect, url_for
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import TextAreaField, SubmitField
from wtforms.validators import DataRequired
from flask_talisman import Talisman
from oqs import KeyEncapsulation
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidTag

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure random secret key
csrf = CSRFProtect(app)

# Configure Talisman for secure HTTP headers
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://cdn.jsdelivr.net', '\'unsafe-inline\''],
    'style-src': ['\'self\'', 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com', '\'unsafe-inline\''],
    'img-src': ['\'self\'', 'data:'],
    'font-src': ['\'self\'', 'https://cdnjs.cloudflare.com', 'data:'],
    'connect-src': ['\'self\''],
}
talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src', 'style-src'],
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_preload=True,
    session_cookie_secure=True,
    session_cookie_http_only=True,
    session_cookie_samesite='Lax',
    frame_options='DENY',
    x_content_type_options='nosniff',
    x_xss_protection=True
)

# Global variable to store kem instance (temporary for demonstration; not production-safe)
stored_kem = None

def base64_encode(data):
    """Convert binary data to base64 string."""
    if isinstance(data, bytes):
        return base64.b64encode(data).decode('utf-8')
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')

def base64_decode(data):
    """Convert base64 string to binary data."""
    try:
        return base64.b64decode(data.encode('utf-8'), validate=True)
    except base64.binascii.Error:
        raise ValueError("Invalid base64-encoded ciphertext")

def generate_keypair():
    """Generate Kyber512 key pair."""
    kem = KeyEncapsulation("Kyber512")
    public_key = kem.generate_keypair()  # Generates public key and associates secret key with kem
    secret_key = kem.export_secret_key()  # Export secret key if supported
    return public_key, secret_key, kem  # Return kem instance to reuse for decryption

def encrypt_with_key(public_key, message):
    """Encrypt a message using Kyber512 KEM and AES-GCM."""
    kem = KeyEncapsulation("Kyber512")
    ciphertext, shared_secret = kem.encap_secret(public_key)
    
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
    else:
        message_bytes = message
    
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(shared_secret[:32]), modes.GCM(iv))
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message_bytes) + padder.finalize()
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    tag = encryptor.tag
    
    encrypted_message = iv + tag + encrypted_data
    return ciphertext, shared_secret, encrypted_message

def decrypt_with_key(ciphertext, encrypted_message, kem):
    """Decrypt using Kyber512 secret key."""
    try:
        # Validate encrypted_message length
        if len(encrypted_message) < 28:
            raise ValueError("Encrypted message is too short to contain IV and tag")
        
        # Decapsulate the shared secret
        try:
            shared_secret = kem.decap_secret(ciphertext)
        except Exception as e:
            raise ValueError(f"Failed to decapsulate shared secret: Invalid or corrupted ciphertext ({str(e)})")
        
        iv = encrypted_message[:12]
        tag = encrypted_message[12:28]
        message_ciphertext = encrypted_message[28:]
        
        cipher = Cipher(algorithms.AES(shared_secret[:32]), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(message_ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        message = unpadder.update(padded_message) + unpadder.finalize()
        return message, shared_secret
    
    except InvalidTag:
        raise ValueError("Decryption failed: Invalid authentication tag, possibly due to incorrect ciphertext or key")
    except ValueError as e:
        raise ValueError(f"Decryption failed: {str(e)}")
    except Exception as e:
        raise ValueError(f"Decryption failed: Unexpected error ({str(e)})")

class EncryptForm(FlaskForm):
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Encrypt')

class DecryptForm(FlaskForm):
    ciphertext = TextAreaField('Ciphertext', validators=[DataRequired()])
    submit = SubmitField('Decrypt')

@app.route('/')
def index():
    """Render the main page."""
    encrypt_form = EncryptForm()
    decrypt_form = DecryptForm()
    return render_template('index.html', encrypt_form=encrypt_form, decrypt_form=decrypt_form)

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    """Generate and store Kyber512 key pair."""
    public_key, secret_key, kem = generate_keypair()
    
    session['public_key'] = base64_encode(public_key)
    session['secret_key'] = base64_encode(secret_key)
    
    # Store kem instance globally (temporary for demonstration; not production-safe)
    global stored_kem
    stored_kem = kem
    
    encrypt_form = EncryptForm()
    decrypt_form = DecryptForm()
    return render_template('index.html', 
                          encrypt_form=encrypt_form,
                          decrypt_form=decrypt_form,
                          public_key=session['public_key'], 
                          secret_key=session['secret_key'])

@app.route('/encrypt', methods=['POST'])
def encrypt():
    """Encrypt using Kyber512 public key."""
    encrypt_form = EncryptForm()
    decrypt_form = DecryptForm()
    if not encrypt_form.validate_on_submit():
        return render_template('index.html', 
                              encrypt_form=encrypt_form,
                              decrypt_form=decrypt_form,
                              error="Invalid form submission")
    
    if 'public_key' not in session:
        return render_template('index.html', 
                              encrypt_form=encrypt_form,
                              decrypt_form=decrypt_form,
                              error="Please generate keys first")
    
    public_key = base64_decode(session['public_key'])
    
    message = encrypt_form.message.data
    if not message:
        return render_template('index.html', 
                              encrypt_form=encrypt_form,
                              decrypt_form=decrypt_form,
                              error="Please enter a message to encrypt",
                              public_key=session.get('public_key', ''),
                              secret_key=session.get('secret_key', ''))
    
    ciphertext, shared_secret, encrypted_message = encrypt_with_key(public_key, message)
    
    session['ciphertext'] = base64_encode(ciphertext)
    session['shared_secret'] = base64_encode(shared_secret)
    session['encrypted_message'] = base64_encode(encrypted_message)
    
    return render_template('index.html',
                          encrypt_form=encrypt_form,
                          decrypt_form=decrypt_form,
                          public_key=session['public_key'],
                          secret_key=session.get('secret_key', ''),
                          ciphertext=session['ciphertext'],
                          shared_secret=session['shared_secret'],
                          original_message=message)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Decrypt using Kyber512 secret key."""
    encrypt_form = EncryptForm()
    decrypt_form = DecryptForm()
    if not decrypt_form.validate_on_submit():
        return render_template('index.html', 
                              encrypt_form=encrypt_form,
                              decrypt_form=decrypt_form,
                              error="Invalid form submission")
    
    if 'secret_key' not in session:
        return render_template('index.html', 
                              encrypt_form=encrypt_form,
                              decrypt_form=decrypt_form,
                              error="Please generate keys first")
    
    try:
        global stored_kem  # Use the stored kem instance
        if not stored_kem:
            return render_template('index.html', 
                                  encrypt_form=encrypt_form,
                                  decrypt_form=decrypt_form,
                                  error="Key encapsulation instance not found. Please generate keys again.",
                                  public_key=session.get('public_key', ''),
                                  secret_key=session.get('secret_key', ''))
        
        # Validate and decode ciphertext
        ciphertext_input = decrypt_form.ciphertext.data
        ciphertext = base64_decode(ciphertext_input)
        
        if 'encrypted_message' not in session:
            return render_template('index.html', 
                                  encrypt_form=encrypt_form,
                                  decrypt_form=decrypt_form,
                                  error="No encrypted message found. Please encrypt a message first.",
                                  public_key=session.get('public_key', ''),
                                  secret_key=session.get('secret_key', ''),
                                  ciphertext=ciphertext_input)
        
        encrypted_message = base64_decode(session['encrypted_message'])
        
        # Validate that the provided ciphertext matches the session ciphertext
        session_ciphertext = session.get('ciphertext', '')
        if base64_encode(ciphertext) != session_ciphertext:
            return render_template('index.html', 
                                  encrypt_form=encrypt_form,
                                  decrypt_form=decrypt_form,
                                  error="Ciphertext does not match the encrypted message. Please use the ciphertext from the encryption step.",
                                  public_key=session.get('public_key', ''),
                                  secret_key=session.get('secret_key', ''),
                                  ciphertext=ciphertext_input)
        
        decrypted_message, recovered_secret = decrypt_with_key(ciphertext, encrypted_message, stored_kem)
        
        return render_template('index.html',
                              encrypt_form=encrypt_form,
                              decrypt_form=decrypt_form,
                              public_key=session.get('public_key', ''),
                              secret_key=session.get('secret_key', ''),
                              ciphertext=ciphertext_input,
                              recovered_secret=base64_encode(recovered_secret),
                              decrypted_message=decrypted_message.decode('utf-8'))
    
    except ValueError as e:
        return render_template('index.html', 
                              encrypt_form=encrypt_form,
                              decrypt_form=decrypt_form,
                              error=f"Decryption error: {str(e)}",
                              public_key=session.get('public_key', ''),
                              secret_key=session.get('secret_key', ''),
                              ciphertext=ciphertext_input)
    except Exception as e:
        error_message = str(e) or "Unknown error during decryption, possibly due to invalid ciphertext"
        return render_template('index.html', 
                              encrypt_form=encrypt_form,
                              decrypt_form=decrypt_form,
                              error=f"Decryption error: {error_message}",
                              public_key=session.get('public_key', ''),
                              secret_key=session.get('secret_key', ''),
                              ciphertext=ciphertext_input)

if __name__ == '__main__':
    app.config['ENV'] = 'development'
    talisman.force_https = False
    app.run(debug=True, host='0.0.0.0', port=5000)