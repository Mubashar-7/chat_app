import tkinter as tk
from tkinter import messagebox
import time
import threading

# ---------------- Prime & Primitive Root Checking ----------------

def is_prime(n):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    r = int(n**0.5)
    for i in range(3, r+1, 2):
        if n % i == 0:
            return False
    return True


def is_primitive_root(g, p):
    if g >= p:
        return False
    required_set = set(range(1, p))
    actual_set = set(pow(g, power, p) for power in range(1, p))
    return required_set == actual_set


# ---------------- DH Functions ----------------

def generate_public_key(g, secret, p):
    return pow(g, secret, p)

def generate_shared_key(public_key, secret, p):
    return pow(public_key, secret, p)

def encrypt_message(message, key):
    return ''.join(chr((ord(c) + key) % 256) for c in message)

def decrypt_message(cipher, key):
    return ''.join(chr((ord(c) - key) % 256) for c in cipher)


# ---------------- Animation ---------------------

def animate_text(canvas, text, start_x, end_x, y):
    obj = canvas.create_text(start_x, y, text=text, font=("Arial", 12), fill="blue")
    steps = 40
    dx = (end_x - start_x) / steps
    for _ in range(steps):
        canvas.move(obj, dx, 0)
        canvas.update()
        time.sleep(0.03)
    canvas.delete(obj)


# ---------------- GUI APP ----------------------

class DHApp:
    def __init__(self, root):
        self.root = root
        root.title("Diffie–Hellman Simulator")
        root.geometry("980x700")
        root.config(bg="white")

        tk.Label(root, text="Diffie–Hellman Key Exchange", 
                 font=("Arial", 20, "bold"), bg="white").pack(pady=10)

        # ---- p and g ----
        top = tk.Frame(root, bg="white")
        top.pack()

        tk.Label(top, text="Prime Number (p):", bg="white").grid(row=0, column=0)
        self.p_entry = tk.Entry(top, width=10)
        self.p_entry.grid(row=0, column=1)
        self.p_entry.bind("<KeyRelease>", self.validate_p)

        self.p_status = tk.Label(top, bg="white", fg="red")
        self.p_status.grid(row=1, column=0, columnspan=2)

        tk.Label(top, text="Primitive Root (g):", bg="white").grid(row=0, column=2)
        self.g_entry = tk.Entry(top, width=10)
        self.g_entry.grid(row=0, column=3)
        self.g_entry.bind("<KeyRelease>", self.validate_g)

        self.g_status = tk.Label(top, bg="white", fg="red")
        self.g_status.grid(row=1, column=2, columnspan=2)

        # --------------- Main Layout -----------------
        main = tk.Frame(root, bg="white")
        main.pack(pady=20)

        # Alice
        alice = tk.Frame(main, bg="white", bd=3, relief="groove", padx=20, pady=20)
        alice.grid(row=0, column=0, padx=40)

        tk.Label(alice, text="Alice", font=("Arial", 18, "bold"), bg="white").pack()

        tk.Label(alice, text="Secret:", bg="white").pack(anchor="w")
        self.alice_secret = tk.Entry(alice, width=15)
        self.alice_secret.pack()

        tk.Button(alice, text="Generate Alice Public Key", command=self.generate_alice).pack(pady=5)

        tk.Label(alice, text="Alice Public Key:", bg="white").pack(anchor="w")
        self.alice_pub = tk.Label(alice, text="---", bg="white")
        self.alice_pub.pack()

        tk.Label(alice, text="Bob Public Key:", bg="white").pack(anchor="w")
        self.alice_bob_pub = tk.Label(alice, text="---", bg="white")
        self.alice_bob_pub.pack()

        tk.Label(alice, text="Shared Key:", bg="white").pack(anchor="w")
        self.alice_shared = tk.Label(alice, text="---", bg="white", fg="green")
        self.alice_shared.pack()

        # Canvas animation
        center = tk.Frame(main, bg="white")
        center.grid(row=0, column=1)
        self.canvas = tk.Canvas(center, width=260, height=200, bg="white", highlightbackground="black")
        self.canvas.pack()

        # Bob
        bob = tk.Frame(main, bg="white", bd=3, relief="groove", padx=20, pady=20)
        bob.grid(row=0, column=2, padx=40)

        tk.Label(bob, text="Bob", font=("Arial", 18, "bold"), bg="white").pack()

        tk.Label(bob, text="Secret:", bg="white").pack(anchor="w")
        self.bob_secret = tk.Entry(bob, width=15)
        self.bob_secret.pack()

        tk.Button(bob, text="Generate Bob Public Key", command=self.generate_bob).pack(pady=5)

        tk.Label(bob, text="Bob Public Key:", bg="white").pack(anchor="w")
        self.bob_pub = tk.Label(bob, text="---", bg="white")
        self.bob_pub.pack()

        tk.Label(bob, text="Alice Public Key:", bg="white").pack(anchor="w")
        self.bob_alice_pub = tk.Label(bob, text="---", bg="white")
        self.bob_alice_pub.pack()

        tk.Label(bob, text="Shared Key:", bg="white").pack(anchor="w")
        self.bob_shared = tk.Label(bob, text="---", bg="white", fg="green")
        self.bob_shared.pack()

        # ---------------- Horizontal Message Layout ----------------

        msg_row = tk.Frame(root, bg="white")
        msg_row.pack(pady=20)

        tk.Label(msg_row, text="Enter Message:", bg="white").grid(row=0, column=0)
        self.msg_entry = tk.Entry(msg_row, width=35)
        self.msg_entry.grid(row=0, column=1, padx=10)

        tk.Button(msg_row, text="Encrypt", command=self.encrypt_message_flow).grid(row=0, column=2, padx=10)

        # Cipher box
        tk.Label(msg_row, text="Cipher:", bg="white").grid(row=0, column=3)
        self.cipher_box = tk.Entry(msg_row, width=20)
        self.cipher_box.grid(row=0, column=4, padx=10)

        # Decrypt button
        tk.Button(msg_row, text="Decrypt", command=self.manual_decrypt).grid(row=0, column=5, padx=10)

        # Message box after decrypt
        tk.Label(msg_row, text="Message:", bg="white").grid(row=0, column=6)
        self.msg_box = tk.Entry(msg_row, width=20)
        self.msg_box.grid(row=0, column=7, padx=10)

        # State
        self.A = None
        self.B = None
        self.shared_key = None

    # ---------------- Validation ----------------

    def validate_p(self, e=None):
        t = self.p_entry.get()
        if t.isdigit() and not is_prime(int(t)):
            self.p_status.config(text="Not a prime")
        else:
            self.p_status.config(text="")

    def validate_g(self, e=None):
        g = self.g_entry.get()
        p = self.p_entry.get()
        if g.isdigit() and p.isdigit() and is_prime(int(p)):
            if not is_primitive_root(int(g), int(p)):
                self.g_status.config(text="Not a primitive root of p")
            else:
                self.g_status.config(text="")
        else:
            self.g_status.config(text="")

    # --------------- Public Keys -----------------

    def generate_alice(self):
        try:
            p = int(self.p_entry.get())
            g = int(self.g_entry.get())
            a = int(self.alice_secret.get())

            self.A = generate_public_key(g, a, p)
            self.alice_pub.config(text=str(self.A))

            threading.Thread(target=self.animate_A_to_B).start()
        except:
            messagebox.showerror("Error", "Invalid Alice input")

    def generate_bob(self):
        try:
            p = int(self.p_entry.get())
            g = int(self.g_entry.get())
            b = int(self.bob_secret.get())

            self.B = generate_public_key(g, b, p)
            self.bob_pub.config(text=str(self.B))

            threading.Thread(target=self.animate_B_to_A).start()
        except:
            messagebox.showerror("Error", "Invalid Bob input")

    # Animation
    def animate_A_to_B(self):
        animate_text(self.canvas, f"A={self.A}", 20, 230, 60)
        self.bob_alice_pub.config(text=str(self.A))
        self.compute_shared()

    def animate_B_to_A(self):
        animate_text(self.canvas, f"B={self.B}", 230, 20, 140)
        self.alice_bob_pub.config(text=str(self.B))
        self.compute_shared()

    # Shared secret
    def compute_shared(self):
        try:
            p = int(self.p_entry.get())
            a = int(self.alice_secret.get())
            b = int(self.bob_secret.get())

            if self.A and self.B:
                k1 = generate_shared_key(self.B, a, p)
                k2 = generate_shared_key(self.A, b, p)

                self.shared_key = k1

                self.alice_shared.config(text=str(k1))
                self.bob_shared.config(text=str(k2))
        except:
            pass

    # ---------------- Encryption Layout ----------------

    def encrypt_message_flow(self):
        if self.shared_key is None:
            messagebox.showerror("Error", "Generate shared key first!")
            return

        msg = self.msg_entry.get()
        cipher = encrypt_message(msg, self.shared_key)

        self.cipher_box.delete(0, tk.END)
        self.cipher_box.insert(0, cipher)

        threading.Thread(target=self.run_animation, args=(msg, cipher)).start()

    def run_animation(self, msg, cipher):
        animate_text(self.canvas, f"Encrypt: {msg}", 20, 230, 40)
        animate_text(self.canvas, f"Cipher: {cipher}", 20, 230, 90)

    # Manual decrypt
    def manual_decrypt(self):
        if self.shared_key is None:
            messagebox.showerror("Error", "No shared key!")
            return

        cipher = self.cipher_box.get()
        decrypted = decrypt_message(cipher, self.shared_key)

        self.msg_box.delete(0, tk.END)
        self.msg_box.insert(0, decrypted)



# ---------------- Run ----------------
root = tk.Tk()
DHApp(root)
root.mainloop()
