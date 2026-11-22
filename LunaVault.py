import customtkinter as ctk
from cryptography.fernet import Fernet
import os 
import json
import webbrowser
import zlib
import hashlib
import base64

DB_FILE = "vault.db"
SALT_SIZE = 20

cipher = None
current_salt = None

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    derived = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(derived[:32])

def read_db(custom_cipher=None):
    use_cipher = custom_cipher if custom_cipher else cipher
    if not os.path.exists(DB_FILE) or use_cipher is None:
        return None
    try:
        with open(DB_FILE, "rb") as f:
            file_data = f.read()
        if len(file_data) <= SALT_SIZE:
            return None
        compressed_data = file_data[SALT_SIZE:]
        encrypted_data = zlib.decompress(compressed_data)
        decrypted_json = use_cipher.decrypt(encrypted_data).decode('utf-8')
        return json.loads(decrypted_json)
    except Exception:
        return None

def write_db(data):
    global current_salt, cipher

    if cipher is None or current_salt is None:
        return
    
    raw_json = json.dumps(data).encode('utf-8')
    encrypted_data = cipher.encrypt(raw_json)
    compressed_data = zlib.compress(encrypted_data)
    with open(DB_FILE, "wb") as f:
        f.write(current_salt + compressed_data)

is_first_time = not os.path.exists(DB_FILE)

def auth_action():
        global is_first_time, cipher, current_salt
        pwd = input_password_login.get().strip()

        if not pwd:
            error_label.configure(text="Veuillez entrer un mot de passe")
            return

        if is_first_time:
            current_salt = os.urandom(SALT_SIZE)
            derived_key = generate_key_from_password(pwd, current_salt)
            cipher = Fernet(derived_key)
            new_db = {
                "credentials": []
            }
            write_db(new_db)
            login.destroy()
            main.deiconify()
            display_credentials()
        else:
            try:
                with open(DB_FILE, "rb") as f:
                    file_data = f.read()
            except Exception:
                error_label.configure(text="Erreur lors de la lecture")
                return

        if len(file_data) <= SALT_SIZE:
            error_label.configure(text="Fichier corrompu")
            return

        salt_from_file = file_data[:SALT_SIZE]
        derived_key = generate_key_from_password(pwd, salt_from_file)
        test_cipher = Fernet(derived_key)

        current_db = read_db(test_cipher)
        if current_db is None:
            error_label.configure(text="Mot de passe incorrect")
            return

        current_salt = salt_from_file
        cipher = test_cipher
        login.destroy()
        main.deiconify()
        display_credentials()

main = ctk.CTk()
main.geometry("800x600")
main.withdraw()

login = ctk.CTkToplevel(main)
login.geometry("360x240")
login.title("Sign In" if is_first_time else "Login")
login.protocol("WM_DELETE_WINDOW", main.destroy)

input_password_login = ctk.CTkEntry(login, placeholder_text="Entrez le mot de passe maître", show="*", width=260)
input_password_login.place(x=50, y=50)
btn_login = ctk.CTkButton(login, text="Créer le coffre" if is_first_time else "Déverrouiller", width=260, command=auth_action)
btn_login.place(x=50, y=100)
error_label = ctk.CTkLabel(login, text="", text_color="red")
error_label.place(x=50, y=145)

input_id = ctk.CTkEntry(main, placeholder_text="Entrez votre identifiant")
input_id.place(x=50, y=120)
input_website = ctk.CTkEntry(main, placeholder_text="Entrez le nom du site web")
input_website.place(x=50, y=80)
input_password = ctk.CTkEntry(main, placeholder_text="Entrez votre mot de passe", show="*")
input_password.place(x=50, y=160)
frame_list = ctk.CTkFrame(main, width=350, height=500)
frame_list.place(x=400, y=50)

def url_open(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    webbrowser.open(url)

def save_credentials(user_id, website, password):
    if not user_id or not website or not password:
        return
    data = read_db()
    if not data:
        return
    data["credentials"].append({"id": user_id, "website": website, "password": password})
    write_db(data)
    input_website.delete(0, "end")
    input_id.delete(0, "end")
    input_password.delete(0, "end")
    display_credentials()

def display_credentials():
    for widget in frame_list.winfo_children():
        widget.destroy()

    data = read_db()
    if not data or not data.get("credentials"):
        return

    for item in data["credentials"]:
        card = ctk.CTkFrame(frame_list)
        card.pack(fill="x", padx=5, pady=5)
        site = item["website"]
        link = ctk.CTkLabel(card, text=f"Website: {site}", text_color="#3B8ED0", cursor="hand2")
        link.pack(anchor="w", padx=10, pady=(5, 0))
        link.bind("<Button-1>", lambda e, s=site: url_open(s))

        text = f"Identifiant: {item['id']}\nPassword: {item['password']}"
        label = ctk.CTkLabel(card, text=text, justify="left")   
        label.pack(anchor="w", padx=10, pady=(0, 5))

btn_save = ctk.CTkButton(main, text="Enregistrer", command=lambda: save_credentials(input_id.get(), input_website.get(), input_password.get()))
btn_save.place(x=50, y=200)

main.mainloop()
