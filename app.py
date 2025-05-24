from flask import Flask, render_template, request
from crypto_utils import encrypt_message, decrypt_message
from utils import save_to_json, load_all_messages

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    encrypted = None
    decrypted = None
    original = None
    password = None
    action = None

    if request.method == "POST":
        message = request.form.get("message", "")  # Safely handle missing fields
        password = request.form.get("password", "")  # Safely handle missing fields
        action = request.form.get("action", "")

        if action == "encrypt" and message and password:
            encrypted = encrypt_message(message, password)
            original = message
            save_to_json(original, encrypted, password)
        elif action == "decrypt" and message and password:
            try:
                decrypted = decrypt_message(message, password)
                encrypted = message
            except ValueError as e:
                decrypted = f"Error: {str(e)}"

    all_messages = load_all_messages()

    return render_template("index.html", original=original, encrypted=encrypted, decrypted=decrypted,
                           password=password, messages=all_messages, action=action)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=True)
