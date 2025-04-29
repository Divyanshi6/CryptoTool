from tkinter import *
from tkinter import ttk, filedialog, messagebox
import base64
from Crypto.Cipher import AES
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime


# Initialize root
root = Tk()
root.title("CryptTool")
root.geometry('800x600')
root.minsize(600, 400)


# Variables
input_text = StringVar()
private_key = StringVar()
mode = StringVar()
Result = StringVar()
algorithm = StringVar(value="Base64")
logs = []
dark_mode = BooleanVar(value=False)

# Theme Colors
light_theme = {"bg": "#F0F8FF", "fg": "black", "header": "#4682B4", "button": "#4682B4"}
dark_theme = {"bg": "#1E1E1E", "fg": "white", "header": "#3A3A3A", "button": "#2E8B57"}

# Algorithm Functions
def encode_base64(key, msg):
    enc = []
    for i in range(len(msg)):
        key_c = key[i % len(key)]
        enc.append(chr((ord(msg[i]) + ord(key_c)) % 256))
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode_base64(key, msg):
    try:
        msg = base64.urlsafe_b64decode(msg).decode()
        dec = []
        for i in range(len(msg)):
            key_c = key[i % len(key)]
            dec.append(chr((256 + ord(msg[i]) - ord(key_c)) % 256))
        return "".join(dec)
    except:
        return "Error: Invalid input or key!"

def encode_caesar(key, msg):
    shift = sum(ord(c) for c in key) % 26
    return ''.join(chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper()
                   else chr((ord(char) - 97 + shift) % 26 + 97) if char.islower()
                   else char for char in msg)

def decode_caesar(key, msg):
    shift = sum(ord(c) for c in key) % 26
    return ''.join(chr((ord(char) - 65 - shift) % 26 + 65) if char.isupper()
                   else chr((ord(char) - 97 - shift) % 26 + 97) if char.islower()
                   else char for char in msg)

def encode_vigenere(key, msg):
    return ''.join(chr((ord(msg[i]) + ord(key[i % len(key)])) % 256) for i in range(len(msg)))

def decode_vigenere(key, msg):
    return ''.join(chr((256 + ord(msg[i]) - ord(key[i % len(key)])) % 256) for i in range(len(msg)))

# AES Encryption and Decryption (using ECB mode for simplicity)
def encode_aes(key, msg):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    padded_msg = msg + (16 - len(msg) % 16) * ' '  # Padding to 16 bytes
    encrypted_msg = cipher.encrypt(padded_msg.encode('utf-8'))
    return base64.b64encode(encrypted_msg).decode()

def decode_aes(key, msg):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    encrypted_msg = base64.b64decode(msg)
    decrypted_msg = cipher.decrypt(encrypted_msg).decode('utf-8').strip()
    return decrypted_msg

def encode_rsa(public_key, msg):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted_msg = cipher.encrypt(msg.encode('utf-8'))
    return base64.b64encode(encrypted_msg).decode()

def decode_rsa(private_key, msg):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted_msg = base64.b64decode(msg)
    decrypted_msg = cipher.decrypt(encrypted_msg).decode('utf-8')
    return decrypted_msg

def rc4(key, msg):
    S = list(range(256))
    j = 0
    out = []
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    for char in msg:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))
    return ''.join(out)

# Atbash Cipher (Reverses the alphabet)
def atbash_encrypt_decrypt(msg):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    reversed_alphabet = alphabet[::-1]
    table = str.maketrans(alphabet + alphabet.upper(), reversed_alphabet + reversed_alphabet.upper())
    return msg.translate(table)

# MD5 Hashing (One-way encryption)
def md5_hash(msg):
    return hashlib.md5(msg.encode('utf-8')).hexdigest()

def show_algorithm_description():
    algo = algorithm.get()
    descriptions = {
        "Base64": {
            "description": """
                Base64 encoding is a method for converting binary data into a text format 
                by encoding it into a radix-64 representation. It is commonly used to 
                transmit binary data over text-based protocols, like email.
            """,
            "working": """
                1. The input binary data is divided into chunks of 6 bits.
                2. Each chunk is mapped to a character in the Base64 alphabet (A-Z, a-z, 0-9, +, /).
                3. If the input data is not a multiple of 3 bytes, padding with "=" is added.
                4. The result is a text representation of the original binary data.
            """
        },
        "Caesar": {
            "description": """
                Caesar Cipher is a substitution cipher where each letter in the plaintext 
                is shifted a certain number of places down or up the alphabet. The key is 
                the number of positions to shift each letter.
            """,
            "working": """
                1. Each letter of the plaintext is shifted by a fixed number of positions.
                2. For example, if the key is 3, 'A' becomes 'D', 'B' becomes 'E', etc.
                3. The shift wraps around the alphabet (e.g., 'Z' shifts to 'C').
                4. The cipher text is generated by shifting each character in the plaintext.
            """
        },
        "Vigenère": {
            "description": """
                Vigenère Cipher is a method of encrypting alphabetic text by using a simple 
                form of polyalphabetic substitution, where each letter of the plaintext is 
                shifted based on a corresponding letter of the keyword.
            """,
            "working": """
                1. A key (which is a word or phrase) is repeated to match the length of the plaintext.
                2. Each letter in the plaintext is shifted by a number of positions based on the corresponding 
                   letter in the key.
                3. The key letter is converted to a number (A=0, B=1, C=2, etc.), and this value is added to the 
                   position of the corresponding plaintext letter.
                4. The result is the ciphertext.
            """
        },
        "AES": {
            "description": """
                AES (Advanced Encryption Standard) is a symmetric encryption algorithm used 
                worldwide to encrypt sensitive data. It operates on fixed-size blocks (128-bits) 
                and supports key sizes of 128, 192, and 256 bits.
            """,
            "working": """
                1. AES operates on blocks of data (128 bits).
                2. The plaintext is transformed into a block of data, then encrypted with a series of 
                   operations, including substitution (S-box), shifting rows, and mixing columns.
                3. A key (128, 192, or 256 bits) is used for both encryption and decryption.
                4. The process involves several rounds (10 for 128-bit keys, 12 for 192-bit keys, 14 for 256-bit keys).
                5. The result is the ciphertext.
            """
        },
        "RSA": {
            "description": """
                RSA is a public-key cryptosystem that is widely used for secure data transmission. 
                It uses two keys: a public key for encryption and a private key for decryption. 
                Its security is based on the difficulty of factoring large prime numbers.
            """,
            "working": """
                1. RSA involves a pair of keys: a public key for encryption and a private key for decryption.
                2. The public key is made available to anyone, while the private key is kept secret.
                3. The message is encrypted using the recipient's public key.
                4. Only the recipient can decrypt the message using their private key.
                5. The security relies on the fact that factoring large numbers is computationally infeasible.
            """
        },
        "RC4": {
            "description": """
                RC4 is a stream cipher that generates a keystream, which is XORed with plaintext 
                to produce ciphertext. It is a symmetric cipher and is used for encrypting data in a 
                byte-by-byte manner.
            """,
            "working": """
                1. RC4 uses a secret key to generate a pseudo-random keystream.
                2. The keystream is then XORed with the plaintext to produce the ciphertext.
                3. Both the sender and receiver must have the same secret key to generate the same keystream.
                4. The encryption and decryption process are the same (symmetric).
            """
        },
        "Atbash": {
            "description": """
                Atbash Cipher is a simple substitution cipher where the alphabet is reversed. 
                The first letter of the alphabet is substituted with the last letter, the second 
                letter with the second-last letter, and so on.
            """,
            "working": """
                1. In Atbash, each letter in the plaintext is substituted with its reverse counterpart 
                   in the alphabet (A ↔ Z, B ↔ Y, etc.).
                2. For example, 'A' becomes 'Z', 'B' becomes 'Y', 'C' becomes 'X', and so on.
                3. The ciphertext is the result of replacing each letter in the plaintext with its reverse counterpart.
            """
        },
        "MD5": {
            "description": """
                MD5 (Message Digest Algorithm 5) is a widely used cryptographic hash function that 
                produces a 128-bit hash value. It is commonly used to verify data integrity, but it is 
                no longer considered secure for cryptographic purposes.
            """,
            "working": """
                1. MD5 processes the input data in blocks of 512 bits.
                2. It applies a series of mathematical operations, including bitwise operations, modular addition, 
                   and logical functions.
                3. After processing, it outputs a 128-bit hash value.
                4. MD5 is commonly used to check file integrity or create checksums, but it is vulnerable to hash collisions.
            """
        }
    }

    
    # Retrieve the selected algorithm's description and working
    selected_algo = descriptions.get(algo, None)
    
    if selected_algo:
        description_text = selected_algo["description"]
        working_text = selected_algo["working"]
    else:
        description_text = "Algorithm description not found."
        working_text = "Algorithm working details not available."

    # Update the Tkinter Label/Text widget with the description and working
    description_label.config(text=description_text)
    working_label.config(text=working_text)


# Main Encoding/Decoding Dispatcher
def Mode():
    text = input_text.get()
    key = private_key.get()
    algo = algorithm.get()
    result = ""
    action = ""

    if not text or not key or not mode.get():
        Result.set("Input, key or mode missing.")
        return

    try:
        if algo == "Base64":
            if mode.get() == 'e':
                result = encode_base64(key, text)
                action = "Base64 Encoded"
            elif mode.get() == 'd':
                result = decode_base64(key, text)
                action = "Base64 Decoded"
        elif algo == "Caesar":
            if mode.get() == 'e':
                result = encode_caesar(key, text)
                action = "Caesar Encoded"
            elif mode.get() == 'd':
                result = decode_caesar(key, text)
                action = "Caesar Decoded"
        elif algo == "Vigenère":
            if mode.get() == 'e':
                result = encode_vigenere(key, text)
                action = "Vigenère Encoded"
            elif mode.get() == 'd':
                result = decode_vigenere(key, text)
                action = "Vigenère Decoded"
        elif algo == "AES":
            if mode.get() == 'e':
                result = encode_aes(key, text)
                action = "AES Encoded"
            elif mode.get() == 'd':
                result = decode_aes(key, text)
                action = "AES Decoded"
        elif algo == "RSA":
            if mode.get() == 'e':
                result = encode_rsa(key, text)
                action = "RSA Encoded"
            elif mode.get() == 'd':
                result = decode_rsa(key, text)
                action = "RSA Decoded"
        elif algo == "RC4":
            if mode.get() == 'e':
                result = rc4(key, text)
                action = "RC4 Encoded"
            elif mode.get() == 'd':
                result = rc4(key, text)
                action = "RC4 Decoded"
        elif algo == "Atbash":
            result = atbash_encrypt_decrypt(text)
            action = "Atbash Encoded/Decoded"
        elif algo == "MD5":
            result = md5_hash(text)
            action = "MD5 Hashed"
        else:
            result = "Unsupported algorithm selected!"
    except Exception as e:
        result = f"Error: {e}"

    Result.set(result)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logs.append(f"[{timestamp}] {action} | Message: {text} | Key: {key} | Result: {result}")

# File Operations (Same as before)
def select_file():
    filepath = filedialog.askopenfilename(title="Select a File")
    if filepath:
        try:
            with open(filepath, 'r') as file:
                input_text.set(file.read())
                messagebox.showinfo("Success", "File content loaded successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")

def save_to_file(content):
    if not content:
        messagebox.showerror("Error", "No content to save!")
        return
    filepath = filedialog.asksaveasfilename(defaultextension=".txt", title="Save File")
    if filepath:
        try:
            with open(filepath, 'w') as file:
                file.write(content)
            messagebox.showinfo("Success", "File saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {e}")

def process_file():
    if not private_key.get() or not mode.get():
        messagebox.showerror("Error", "Please enter a key and select a mode!")
        return
    Mode()
    save_to_file(Result.get())

# Logs
def show_logs():
    log_window = Toplevel(root)
    log_window.title("History and Logs")
    log_window.geometry("600x400")
    log_window.configure(bg=get_theme()["bg"])

    Label(log_window, text="History and Logs", font="Arial 16 bold", bg=get_theme()["header"], fg=get_theme()["fg"]).pack(fill="x")
    log_text = Text(log_window, wrap="word", font="Arial 10", bg="white")
    log_text.pack(padx=10, pady=10, fill="both", expand=True)

    for entry in logs:
        log_text.insert(END, entry + "\n")
    log_text.config(state="disabled")

def export_logs():
    if not logs:
        messagebox.showinfo("Info", "No logs to export.")
        return

    filepath = filedialog.asksaveasfilename(defaultextension=".txt", title="Export Logs As")
    if filepath:
        try:
            with open(filepath, 'w') as file:
                file.write("\n".join(logs))
            messagebox.showinfo("Success", "Logs exported successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {e}")


def Reset():
    input_text.set("")
    private_key.set("")
    mode.set("")
    Result.set("")

def Exit():
    root.destroy()

def toggle_theme():
    dark_mode.set(not dark_mode.get())
    apply_theme()

def get_theme():
    return dark_theme if dark_mode.get() else light_theme

def apply_theme():
    th = get_theme()
    root.configure(bg=th["bg"])
    for frame in [header_frame, input_frame, button_frame]:
        frame.configure(bg=th["bg"])
    header_label.configure(bg=th["header"], fg=th["fg"])
    for child in input_frame.winfo_children():
        if isinstance(child, Label):
            child.configure(bg=th["bg"], fg=th["fg"])
    for child in button_frame.winfo_children():
        if isinstance(child, Button):
            child.configure(bg=th["button"], fg="white", activebackground="#FFD700", activeforeground="black")


# UI Layout
header_frame = Frame(root, padx=10, pady=10)
header_frame.pack(fill="x")
header_label = Label(header_frame, text="SECRET MESSAGE ENCRYPTOR/DECRYPTOR", font="Arial 16 bold")
header_label.pack()

input_frame = Frame(root, padx=20, pady=10)
input_frame.pack(fill="both", expand=True)

Label(input_frame, text="Enter Message:", font="Arial 12 bold").grid(row=0, column=0, sticky="w", pady=5)
Entry(input_frame, font="Arial 10", textvariable=input_text).grid(row=0, column=1, pady=5, padx=10, sticky="ew")

Label(input_frame, text="Enter Key:", font="Arial 12 bold").grid(row=1, column=0, sticky="w", pady=5)
Entry(input_frame, font="Arial 10", textvariable=private_key).grid(row=1, column=1, pady=5, padx=10, sticky="ew")

Label(input_frame, text="Mode (e/d):", font="Arial 12 bold").grid(row=2, column=0, sticky="w", pady=5)
Entry(input_frame, font="Arial 10", textvariable=mode).grid(row=2, column=1, pady=5, padx=10, sticky="ew")

Label(input_frame, text="Select Algorithm:", font="Arial 12 bold").grid(row=3, column=0, sticky="w", pady=5)
ttk.Combobox(input_frame, textvariable=algorithm, values=["Base64", "Caesar", "Vigenère","AES","RSA","RC4","Atbash","Md4"]).grid(row=3, column=1, pady=5, padx=10, sticky="ew")
algorithm_dropdown = OptionMenu(root, algorithm, *["Base64", "Caesar", "Vigenère", "AES", "RSA", "RC4", "Atbash", "MD5"], command=lambda _: show_algorithm_description())
algorithm_dropdown.bind("<<ComboboxSelected>>", lambda event: show_algorithm_description())


Label(input_frame, text="Result:", font="Arial 12 bold").grid(row=4, column=0, sticky="w", pady=5)
Entry(input_frame, font="Arial 10", textvariable=Result, state="readonly").grid(row=4, column=1, pady=5, padx=10, sticky="ew")

input_frame.columnconfigure(1, weight=1)


# Description Section Frame
desc_frame = Frame(root, bd=2, relief=GROOVE, padx=10, pady=10, bg=light_theme["bg"])
desc_frame.pack(fill=BOTH, expand=True, padx=10, pady=(10, 0))

# Description Title
Label(desc_frame, text="Algorithm Description", font=("Arial", 14, "bold"), bg=light_theme["bg"], fg=light_theme["fg"]).pack(anchor=W)

# Description Label
description_label = Label(desc_frame, text="", justify=LEFT, wraplength=750, bg=light_theme["bg"], fg=light_theme["fg"], font=("Arial", 11))
description_label.pack(anchor=W, pady=(5, 10))

# Working Title
Label(desc_frame, text="How it Works", font=("Arial", 14, "bold"), bg=light_theme["bg"], fg=light_theme["fg"]).pack(anchor=W)

# Working Label
working_label = Label(desc_frame, text="", justify=LEFT, wraplength=750, bg=light_theme["bg"], fg=light_theme["fg"], font=("Arial", 11))
working_label.pack(anchor=W, pady=(5, 10))

button_frame = Frame(root)
button_frame.pack(fill="x", pady=20)

buttons = [
    ("RESULT", Mode),
    ("RESET", Reset),
    ("EXIT", Exit),
    ("OPEN FILE", select_file),
    ("PROCESS FILE", process_file),
    ("SHOW LOGS", show_logs),
    ("EXPORT LOGS", export_logs),
    ("TOGGLE THEME", toggle_theme),
    ("SHOW DESCRIPTION", show_algorithm_description)
]

for idx, (text, cmd) in enumerate(buttons):
    btn = Button(button_frame, text=text, command=cmd, padx=10, pady=5)
    btn.grid(row=0, column=idx, padx=5, sticky="ew")
    button_frame.grid_columnconfigure(idx, weight=1)

# Final setup
apply_theme()
root.mainloop()
