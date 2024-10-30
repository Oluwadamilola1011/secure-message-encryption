import streamlit as st
import hashlib
import base64

# Set up Streamlit page title and layout with colored heading
st.markdown("<h1 style='color: #b565c5;'>🔐 Secure Your Messages</h1>", unsafe_allow_html=True)
st.write("Secure your text with custom password-based encryption.")

# This function generates a numeric key from a password using SHA-256 hashing
def generate_key_from_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    key = int(hashed_password, 16) % 256  # Limit the key to a range of 0-255
    return key

# This function encrypts the text and returns a Base64 encoded string
def encrypt(text, key):
    result = bytearray()
    for letter in text:
        encrypted_char = ord(letter) ^ key
        result.append(encrypted_char)
    return base64.b64encode(result).decode()

# This function decrypts the Base64 encoded string
def decrypt(encrypted_text, key):
    encrypted_bytes = base64.b64decode(encrypted_text)
    result = ''
    for byte in encrypted_bytes:
        decrypted_char = byte ^ key
        result += chr(decrypted_char)
    return result

# --- UI for Encryption ---
st.subheader("🔒 Encryption")
text = st.text_input("Enter a message to encrypt:")
password = st.text_input("Enter a password:", type="password")
st.write("**Note:** Please remember the password you use, as you'll need it to decrypt your messages.")

if st.button("Encrypt"):
    encryption_key = generate_key_from_password(password)
    encrypted_message = encrypt(text, encryption_key)
    st.success(f"🔑 Encrypted Message: {encrypted_message}")
    st.code(encrypted_message)
    st.session_state.encrypted_copied = encrypted_message

# --- UI for Decryption ---
st.subheader("🔓 Decryption")
if st.checkbox("Want to decrypt a message?"):
    encrypted_text = st.text_input("Enter the encrypted message:")
    decryption_password = st.text_input("Enter the password:", type="password")
    if st.button("Decrypt"):
        decryption_key = generate_key_from_password(decryption_password)
        try:
            decrypted_message = decrypt(encrypted_text, decryption_key)
            st.success(f"🔑 Decrypted Message: {decrypted_message}")
            st.code(decrypted_message)
            st.session_state.decrypted_copied = decrypted_message
        except Exception as e:
            st.error("Decryption failed. Check the password and message.")