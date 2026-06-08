import pickle
import tkinter as tk
import customtkinter as tkcu
import socket
import threading
from tkinter import messagebox
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import pygame
import pygame.freetype
import queue
import const

__author__ = "Ben"
IP = "192.168.1.127"
PORT = 8080
SIZE_HEADER_FORMAT = "00000000|"
size_header_size = len(SIZE_HEADER_FORMAT)
TCP_DEBUG = True
LEN_TO_PRINT = 100

tkcu.set_appearance_mode("dark")

FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_LABEL = ("Segoe UI", 11)
FONT_ENTRY = ("Segoe UI", 12)
FONT_BTN = ("Segoe UI", 12, "bold")

CLR_BG = "#1a1a2e"
CLR_SURFACE = "#16213e"
CLR_ACCENT = "#0f3460"
CLR_HILIGHT = "#e94560"
CLR_TEXT = "#eaeaea"
CLR_MUTED = "#8899aa"

ENTRY_KWARGS = dict(
    font=FONT_ENTRY,
    fg_color="#0d1b2a",
    border_color="#0f3460",
    border_width=2,
    text_color=CLR_TEXT,
    corner_radius=8,
    height=38,
    width=220,
)

LABEL_KWARGS = dict(
    font=FONT_LABEL,
    text_color=CLR_MUTED,
)

BTN_PRIMARY = dict(
    font=FONT_BTN,
    fg_color=CLR_HILIGHT,
    hover_color="#c73652",
    text_color="white",
    corner_radius=8,
    height=40,
)

BTN_SECONDARY = dict(
    font=("Segoe UI", 11),
    fg_color=CLR_ACCENT,
    hover_color="#1a4a80",
    text_color=CLR_TEXT,
    corner_radius=8,
    height=36,
)


class HandelCommunication(socket.socket):
    def __init__(self):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((IP, PORT))
        self.online_users = []
        self._response_queue = queue.Queue()
        self.aes_key = AESGCM.generate_key(bit_length=256)
        self.aes_obj = AESGCM(self.aes_key)
        self.associated_data = b"Bentheking"
        # Start listening thread
        threading.Thread(target=self._listen_loop, daemon=True).start()

    def _listen_loop(self):
        """Continuously listen for responses in background thread"""
        while True:
            try:
                data = self._raw_recv()
                if data:
                    self._response_queue.put(data)
            except Exception as e:
                print(f"Listening error: {e}")
                break

    def wait_response(self):
        """Get next queued response"""
        try:
            return self._response_queue.get(timeout=5)
        except queue.Empty:
            return None

    def _raw_recv(self, buffersize=2048, flags=0):
        size_header = b''
        while len(size_header) < size_header_size:
            chunk = super().recv(size_header_size - len(size_header), flags)
            if not chunk:
                return ''
            size_header += chunk
        try:
            data_len = int(size_header[:size_header_size - 1])
        except ValueError:
            return ''
        data = b''
        while len(data) < data_len:
            chunk = super().recv(data_len - len(data), flags)
            if not chunk:
                return ''
            data += chunk
        if TCP_DEBUG:
            print(f"\nRecv({data_len})>>>{data[:LEN_TO_PRINT]}")

        # Raw (unencrypted) data — key exchange responses, public key PEM, or DH parameters PEM
        try:
            decoded = data.decode()
            if decoded.startswith("KeyT") or decoded.startswith("KeyF") or \
                    decoded.startswith("-----BEGIN PUBLIC KEY-----") or \
                    decoded.startswith("-----BEGIN DH PARAMETERS-----"):
                return decoded
        except Exception:
            pass

        # Encrypted message
        ciphertext = data[:-12]
        nonce = data[-12:]
        try:
            return self.aes_obj.decrypt(nonce, ciphertext, self.associated_data).decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return ''

    def send(self, bdata, flags=0, key=False):
        if type(bdata) != bytes:
            bdata = bdata.encode()
        if key:
            header_data = str(len(bdata)).zfill(size_header_size - 1).encode() + b"|"
            super().send(header_data + bdata)
            if TCP_DEBUG:
                print(f"\nSent(raw {len(bdata)})>>>{bdata[:LEN_TO_PRINT]}")
        else:
            nonce = os.urandom(12)
            encode_bdata = self.aes_obj.encrypt(nonce, bdata, self.associated_data)
            header_data = str(len(encode_bdata) + len(nonce)).zfill(size_header_size - 1).encode() + b"|"
            super().send(header_data + encode_bdata + nonce)
            if TCP_DEBUG:
                print(f"\nSent(enc {len(encode_bdata)})>>>{bdata[:LEN_TO_PRINT]}")


class SignUpPage(tk.Frame):
    def __init__(self, parent, controller, client):
        super().__init__(parent, bg=CLR_BG)
        self.client = client
        self.controller = controller
        self.button = button_thread(client=self.client)

        self.var_user = tk.StringVar()
        self.var_email = tk.StringVar()
        self.var_pw = tk.StringVar()
        self.var_confirm = tk.StringVar()

        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        tkcu.CTkLabel(self, text="Create Account", font=FONT_TITLE,
                      text_color=CLR_HILIGHT, fg_color=CLR_BG).grid(
            row=0, column=0, columnspan=2, pady=(30, 20))

        self._make_field("Username", self.var_user, row=1)
        self._make_field("Email", self.var_email, row=2)
        self._make_field("Password", self.var_pw, row=3, secret=True)
        self._make_field("Confirm Password", self.var_confirm, row=4, secret=True)

        tkcu.CTkButton(self, text="Register", command=self.handle_registration,
                       **BTN_PRIMARY).grid(row=5, column=0, columnspan=2, pady=(20, 6))

        tkcu.CTkButton(self, text="Already have an account? Login",
                       command=lambda: controller.show_frame(LoginPage),
                       **BTN_SECONDARY).grid(row=6, column=0, columnspan=2, pady=4)

    def _make_field(self, label_text, textvariable, row, secret=False):
        tkcu.CTkLabel(self, text=label_text, **LABEL_KWARGS,
                      fg_color=CLR_BG).grid(row=row, column=0, sticky="e", padx=(10, 6), pady=6)
        kwargs = dict(ENTRY_KWARGS)
        if secret:
            kwargs["show"] = "●"
        tkcu.CTkEntry(self, textvariable=textvariable, **kwargs).grid(
            row=row, column=1, sticky="w", padx=(6, 10), pady=6)

    def handle_registration(self):
        user = self.var_user.get().strip()
        email = self.var_email.get().strip()
        pw = self.var_pw.get()
        confirm = self.var_confirm.get()

        if not user or not email or not pw:
            messagebox.showwarning("Missing Fields", "All fields are required!")
        elif pw != confirm:
            messagebox.showerror("Password Mismatch", "Passwords do not match!")
        else:
            worked = self.button.button_Signup(user, email, pw)
            if worked:
                self.controller.show_frame(LoginPage)
            else:
                messagebox.showinfo("Already Registered", "This user already exists!")


class LoginPage(tk.Frame):
    def __init__(self, parent, controller, client):
        super().__init__(parent, bg=CLR_BG)
        self.client = client
        self.controller = controller
        self.button = button_thread(client=self.client)

        self.var_user = tk.StringVar()
        self.var_password = tk.StringVar()

        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        tkcu.CTkLabel(self, text="Welcome Back", font=FONT_TITLE,
                      text_color=CLR_HILIGHT, fg_color=CLR_BG).grid(
            row=0, column=0, columnspan=2, pady=(30, 20))

        self.segmented_button = tkcu.CTkSegmentedButton(
            self,
            values=["RSA", "Diffie-Hellman"],
            command=self.encode_button,
            font=("Segoe UI", 11, "bold"),
            fg_color=CLR_ACCENT,
            selected_color=CLR_HILIGHT,
            selected_hover_color="#c73652",
            unselected_color=CLR_ACCENT,
            unselected_hover_color="#1a4a80",
            text_color=CLR_TEXT,
            corner_radius=8,
        )
        self.segmented_button.grid(row=3, column=0, columnspan=2, pady=(0, 10), padx=20, sticky="ew")

        self._make_field("Username", self.var_user, row=4)
        self._make_field("Password", self.var_password, row=5, secret=True)

        tkcu.CTkButton(self, text="Login", command=self.handle_login,
                       **BTN_PRIMARY).grid(row=10, column=0, columnspan=2, pady=(20, 6))

        tkcu.CTkButton(self, text="Don't have an account? Sign Up",
                       command=lambda: controller.show_frame(SignUpPage),
                       **BTN_SECONDARY).grid(row=12, column=0, columnspan=2, pady=4)

        tkcu.CTkButton(self, text="Forgot password?",
                       command=lambda: controller.show_frame(ForgotPassword),
                       **BTN_SECONDARY).grid(row=13, column=0, columnspan=2, pady=4)

    def _make_field(self, label_text, textvariable, row, secret=False):
        tkcu.CTkLabel(self, text=label_text, **LABEL_KWARGS,
                      fg_color=CLR_BG).grid(row=row, column=0, sticky="e", padx=(10, 6), pady=6)
        kwargs = dict(ENTRY_KWARGS)
        if secret:
            kwargs["show"] = "●"
        tkcu.CTkEntry(self, textvariable=textvariable, **kwargs).grid(
            row=row, column=1, sticky="w", padx=(6, 10), pady=6)

    def handle_login(self):
        user = self.var_user.get().strip()
        password = self.var_password.get()
        encryption = self.segmented_button.get()
        if not user or not password or not encryption:
            messagebox.showwarning("Missing Fields", "All fields are required!")
        else:
            worked = self.button.button_Login(user, password)
            if worked == "LoginS":
                self.controller.show_frame(EmailPassword)
                self.controller.frames[EmailPassword].start_timer_display("login")
            elif worked == "LoginF":
                messagebox.showinfo("Login Failed", "Wrong username or password!")
            elif worked == "LoginNotAb":
                messagebox.showinfo("Login Failed", "This user is already logged in!")

    def encode_button(self, encryption):
        worked = self.button.button_encrypt(encryption)
        if worked:
            if encryption == "RSA":
                threading.Thread(target=self.RSA, daemon=True).start()
            elif encryption == "Diffie-Hellman":
                threading.Thread(target=self.Diffie_Hellman, daemon=True).start()
        else:
            messagebox.showinfo("Support", "Don't support this method")

    def RSA(self):
        # Request server's public key
        self.client.send("PublicKey", key=True)
        pem_public = self.client.wait_response()

        # Load the public key object
        public_key = serialization.load_pem_public_key(pem_public.encode())

        # Encrypt our AES key with the server's public key
        encrypted_aes_key = public_key.encrypt(
            self.client.aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Send encrypted AES key — raw, not AES-encrypted
        self.client.send(b"aes:" + encrypted_aes_key, key=True)
        print("RSA key exchange complete.")

    def Diffie_Hellman(self):
        # Receive DH parameters PEM from server and deserialize
        params_pem = self.client.wait_response()
        parameters = serialization.load_pem_parameters(params_pem.encode())

        # Generate client private key and derive public key
        b = parameters.generate_private_key()
        B = b.public_key()
        B_pem = B.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        # Send our public key to server — unencrypted (no AES yet)
        self.client.send(B_pem, key=True)

        # Receive server's public key
        A_pem = self.client.wait_response()
        A = serialization.load_pem_public_key(A_pem.encode())

        # Derive shared AES key
        shared_key = b.exchange(A)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(shared_key)

        # Update the client's AES object with the derived key
        self.client.aes_key = derived_key
        self.client.aes_obj = AESGCM(derived_key)

        # Tell server our derived key — unencrypted (AES not yet confirmed on server)
        self.client.send(b"aes:" + derived_key, key=True)
        print("Diffie-Hellman key exchange complete.")


class ForgotPassword(tk.Frame):
    def __init__(self, parent, controller, client):
        super().__init__(parent, bg=CLR_BG)
        self.client = client
        self.controller = controller
        self.button = button_thread(client=self.client)
        self.var_user = tk.StringVar()

        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        tkcu.CTkLabel(self, text="Forgot Password", font=FONT_TITLE,
                      text_color=CLR_HILIGHT, fg_color=CLR_BG).grid(
            row=0, column=0, columnspan=2, pady=(30, 20))

        self._make_field("Username", self.var_user, row=1)

        self.lbl_status = tkcu.CTkLabel(self, text="", font=FONT_LABEL,
                                        fg_color=CLR_BG, text_color=CLR_MUTED)
        self.lbl_status.grid(row=2, column=0, columnspan=2, pady=4)

        tkcu.CTkButton(self, text="Send verification email", command=self.handle_forgot,
                       **BTN_PRIMARY).grid(row=3, column=0, columnspan=2, pady=(16, 6))

        tkcu.CTkButton(self, text="Back to Login",
                       command=lambda: controller.show_frame(LoginPage),
                       **BTN_SECONDARY).grid(row=4, column=0, columnspan=2, pady=4)

    def handle_forgot(self):
        user = self.var_user.get().strip()
        if not user:
            messagebox.showwarning("Missing Fields", "Please enter your username.")
            return
        self.client.send(f"ForgotPassword:{user}")
        resp = self.client.wait_response()
        if resp == "ForgotS":
            self.controller.show_frame(EmailPassword)
            self.controller.frames[EmailPassword].start_timer_display("forgot")
        else:
            messagebox.showerror("Not Found", "No account with that username.")

    def _make_field(self, label_text, textvariable, row, secret=False):
        tkcu.CTkLabel(self, text=label_text, **LABEL_KWARGS,
                      fg_color=CLR_BG).grid(row=row, column=0, sticky="e", padx=(10, 6), pady=6)
        kwargs = dict(ENTRY_KWARGS)
        if secret:
            kwargs["show"] = "●"
        tkcu.CTkEntry(self, textvariable=textvariable, **kwargs).grid(
            row=row, column=1, sticky="w", padx=(6, 10), pady=6)


class EmailPassword(tk.Frame):
    def __init__(self, parent, controller, client):
        super().__init__(parent, bg=CLR_BG)
        self.client = client
        self.controller = controller
        self.button = button_thread(client=self.client)
        self.var_password = tk.StringVar()
        self._waiting = False
        self._tick_id = None
        self._watch_id = None
        self._source = ""

        tkcu.CTkLabel(self, text="Check your mailbox", font=FONT_TITLE,
                      text_color=CLR_HILIGHT, fg_color=CLR_BG).grid(
            row=0, column=0, columnspan=2, pady=(30, 20))

        self._make_field("Code", self.var_password, row=1, secret=True)

        self.lbl_timer = tkcu.CTkLabel(self, text="⏳ 5:00 remaining", font=FONT_LABEL,
                                       fg_color=CLR_BG, text_color=CLR_MUTED)
        self.lbl_timer.grid(row=2, column=0, columnspan=2, pady=4)

        tkcu.CTkButton(self, text="Check", command=self.handle_password_check,
                       **BTN_PRIMARY).grid(row=3, column=0, columnspan=2, pady=(20, 6))

    def start_timer_display(self, source):
        self._waiting = False
        if self._tick_id is not None:
            self.after_cancel(self._tick_id)
            self._tick_id = None
        if self._watch_id is not None:
            self.after_cancel(self._watch_id)
            self._watch_id = None

        self._source = source
        self._seconds_left = 300
        self._waiting = True
        self._tick_id = self.after(0, self._tick)
        # Start polling from main thread instead of daemon thread
        self._watch_id = self.after(100, self._watch_for_timeout)

    def _tick(self):
        self._tick_id = None
        if not self._waiting:
            return
        mins, secs = divmod(self._seconds_left, 60)
        self.lbl_timer.configure(text=f"⏳ {mins}:{secs:02d} remaining")
        if self._seconds_left > 0:
            self._seconds_left -= 1
            self._tick_id = self.after(1000, self._tick)

    def _watch_for_timeout(self):
        """Poll queue from main thread every 100ms - no background thread!"""
        self._watch_id = None

        if not self._waiting:
            return

        try:
            resp = self.client._response_queue.get(timeout=0.01)
            if resp == "EmailTimeout":
                self._waiting = False
                self._on_timeout()
            else:
                # Put it back if it's not what we wanted
                self.client._response_queue.put(resp)
        except queue.Empty:
            pass

        # Schedule next check
        if self._waiting:
            self._watch_id = self.after(100, self._watch_for_timeout)

    def _on_timeout(self):
        self._waiting = False
        if self._tick_id is not None:
            self.after_cancel(self._tick_id)
            self._tick_id = None
        messagebox.showinfo("Time Expired", "The email verification code has expired.\nPlease log in again.")
        self.controller.show_frame(LoginPage)

    def handle_password_check(self):
        password = self.var_password.get()
        self._waiting = False
        if self._watch_id is not None:
            self.after_cancel(self._watch_id)
            self._watch_id = None

        answer = self.button.email_password_check(password)
        if answer and self._source == "login":
            self.controller.show_frame(MenuWordle)
        elif answer and self._source == "forgot":
            user = self.controller.frames[ForgotPassword].var_user.get().strip()
            self.controller.frames[ResetPassword].set_user(user)
            self.controller.show_frame(ResetPassword)
        else:
            self._waiting = True
            self._watch_id = self.after(100, self._watch_for_timeout)
            messagebox.showinfo("Wrong code", "The code you entered is incorrect.")

    def _make_field(self, label_text, textvariable, row, secret=False):
        tkcu.CTkLabel(self, text=label_text, **LABEL_KWARGS,
                      fg_color=CLR_BG).grid(row=row, column=0, sticky="e", padx=(10, 6), pady=6)
        kwargs = dict(ENTRY_KWARGS)
        if secret:
            kwargs["show"] = "●"
        tkcu.CTkEntry(self, textvariable=textvariable, **kwargs).grid(
            row=row, column=1, sticky="w", padx=(6, 10), pady=6)


class ResetPassword(tk.Frame):
    def __init__(self, parent, controller, client):
        super().__init__(parent, bg=CLR_BG)
        self.client = client
        self.controller = controller
        self.button = button_thread(client=self.client)
        self._user = ""
        self.var_pw = tk.StringVar()
        self.var_confirm = tk.StringVar()

        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        tkcu.CTkLabel(self, text="Reset Password", font=FONT_TITLE,
                      text_color=CLR_HILIGHT, fg_color=CLR_BG).grid(
            row=0, column=0, columnspan=2, pady=(30, 20))

        self._make_field("New Password", self.var_pw, row=1, secret=True)
        self._make_field("Confirm Password", self.var_confirm, row=2, secret=True)

        self.lbl_status = tkcu.CTkLabel(self, text="", font=FONT_LABEL,
                                        fg_color=CLR_BG, text_color=CLR_MUTED)
        self.lbl_status.grid(row=3, column=0, columnspan=2, pady=4)

        tkcu.CTkButton(self, text="Reset Password", command=self.handle_reset,
                       **BTN_PRIMARY).grid(row=4, column=0, columnspan=2, pady=(16, 6))

    def set_user(self, user):
        self._user = user

    def handle_reset(self):
        pw = self.var_pw.get()
        confirm = self.var_confirm.get()
        if not pw:
            messagebox.showwarning("Missing Fields", "Please enter a new password.")
            return
        if pw != confirm:
            messagebox.showerror("Mismatch", "Passwords do not match!")
            return
        resp = self.button.button_reset_password(self._user, pw)
        if resp:
            messagebox.showinfo("Success", "Password reset successfully!")
            self.var_pw.set("")
            self.var_confirm.set("")
            self.controller.show_frame(MenuWordle)
        else:
            self.lbl_status.configure(text="Reset failed. Try again.", text_color=CLR_HILIGHT)

    def _make_field(self, label_text, textvariable, row, secret=False):
        tkcu.CTkLabel(self, text=label_text, **LABEL_KWARGS,
                      fg_color=CLR_BG).grid(row=row, column=0, sticky="e", padx=(10, 6), pady=6)
        kwargs = dict(ENTRY_KWARGS)
        if secret:
            kwargs["show"] = "●"
        tkcu.CTkEntry(self, textvariable=textvariable, **kwargs).grid(
            row=row, column=1, sticky="w", padx=(6, 10), pady=6)


class MenuWordle(tk.Frame):
    def __init__(self, parent, controller, client):
        super().__init__(parent, bg=CLR_BG)
        self.client = client
        self.controller = controller
        self.button = button_thread(client=self.client)

        # 1. Title
        tkcu.CTkLabel(self, text="Wordle Game", font=FONT_TITLE,
                      text_color=CLR_HILIGHT, fg_color=CLR_BG).pack(pady=(30, 10))

        # 2. Word Length Slider Section
        tkcu.CTkLabel(self, text="Select Word Length:", font=("Arial", 14),
                      text_color="white").pack(pady=(10, 0))

        # Variable to store the slider value
        self.word_len_var = tk.IntVar(value=5)

        # Slider (from 5 to 8, with 3 steps to ensure whole numbers)
        self.slider = tkcu.CTkSlider(self, from_=5, to=8,
                                     number_of_steps=3,
                                     variable=self.word_len_var,
                                     button_color=CLR_HILIGHT,
                                     progress_color=CLR_HILIGHT)
        self.slider.pack(pady=(5, 10))

        # Label that updates to show the selected number
        self.lbl_value = tkcu.CTkLabel(self, textvariable=self.word_len_var, font=("Arial", 16, "bold"))
        self.lbl_value.pack()

        # 3. Action Buttons
        tkcu.CTkButton(self, text="Start Game Alone",
                       command=self.start_alone, **BTN_PRIMARY).pack(pady=10)

        tkcu.CTkButton(self, text="Invite Someone",
                       command=self.invite_friend, **BTN_PRIMARY).pack(pady=10)

        tkcu.CTkButton(self, text="Back to Login",
                       command=self.handle_logout,
                       **BTN_SECONDARY).pack(pady=(20, 10))

        # Status label for errors/notifications
        self.lbl_status = tkcu.CTkLabel(self, text="", text_color="#facc15")
        self.lbl_status.pack(pady=5)

    def start_alone(self):
        word_size = self.word_len_var.get()
        print(f"Starting solo game with {word_size} letters...")
        self.controller.run_game(solo=True,length=word_size)
    def invite_friend(self):
        word_size = self.word_len_var.get()
        print(f"Sending invite for a {word_size}-letter game...")
        # self.client.send(f"Invite:{friend_name};{word_size}")
    def handle_logout(self):
        toDisconnect = self.button.button_Logout()
        if toDisconnect:
            self.controller.show_frame(LoginPage)
        else:
            self.lbl_status.configure(text="Server error", text_color="#facc15")

PAGESNAMES = [LoginPage, SignUpPage, ForgotPassword, ResetPassword, MenuWordle, EmailPassword]


class MainApp(tk.Tk):
    def __init__(self, client):
        super().__init__()
        self.title("Encode Chat")
        self.geometry("520x420")
        self.configure(bg=CLR_BG)
        self.resizable(False, False)
        self.client = client
        self.words = self.load_words()
        container = tk.Frame(self, bg=CLR_BG)
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        self.frames = {}
        for F in PAGESNAMES:
            frame = F(parent=container, controller=self, client=client)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(LoginPage)

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()

    def run_game(self, solo,length):
        self.withdraw()
        try:
            self.client.send(f"{const.play_solo};{length}")
            accept = self.client.wait_response()
            if accept == const.start_solo_game:
                self.start_pygame_loop(solo,length)
            else:
                print("Server shoutdown")
        finally:
            #Once Pygame is closed, bring the Tkinter window back
            self.deiconify()

    def start_pygame_loop(self,solo,length):
        game_won = False
        game_lost = False
        pygame.init()
        WINDOW_WIDTH = 700
        WINDOW_HEIGHT = 500
        BOX_SIZE = 60
        GAP = 10
        ROWS = 6
        COLS = length
        try:
            font_path = os.path.join(os.environ['WINDIR'], 'Fonts', 'arial.ttf')

            if os.path.exists(font_path):
                font = pygame.freetype.Font(font_path, 40)
            else:
                font = pygame.freetype.Font('david', 40)
        except Exception as e:
            print(f"Font error: {e}")
            font = pygame.freetype.Font(None, 40)
        board = [["" for box in range(COLS)] for box in range(ROWS)]
        colors_board = [[const.background_color for _ in range(COLS)] for _ in range(ROWS)]
        error = False
        current_row = 0
        current_col = 0
        # Initialize Pygame inside the method
        screen = pygame.display.set_mode((WINDOW_WIDTH, WINDOW_HEIGHT))
        pygame.display.set_caption("Wordle Game")
        clock = pygame.time.Clock()

        finish = False
        while not finish:
            for event in pygame.event.get():#handels all the game inputs.
                if event.type == pygame.QUIT:
                    finish = True
                if event.type == pygame.KEYDOWN:
                    #Handle Backspace
                    if event.key == pygame.K_BACKSPACE:
                        if current_col > 0:
                            current_col -= 1
                            board[current_row][current_col] = ""
                            error = False
                    #Handle Enter
                    elif event.key == pygame.K_RETURN:
                        if  self.check_line(board, current_row, COLS) and current_col == COLS and current_row <= ROWS - 1:
                            result = self.submit_row("".join(board[current_row]))
                            if result == True:
                                for i in range(COLS):
                                    colors_board[current_row][i] = (106, 170, 100)  # Green
                                game_won = True
                            for i in range(COLS):
                                colors_board[current_row][i] = result[i]
                            current_row += 1
                            current_col = 0
                            error = False
                        if  current_row == ROWS:
                            game_lost = True

                        else:
                            error = True
                    #Handle Hebrew Input
                    else:
                        char = event.unicode
                        # Check if character is a Hebrew letter(Unicode range)
                        if '\u05d0' <= char <= '\u05ea':
                            if current_col < COLS:
                                board[current_row][current_col] = char
                                current_col += 1
                                error = False
            screen.fill(const.background_color)

            # Calculate grid dimensions
            grid_width = (COLS * BOX_SIZE) + ((COLS - 1) * GAP)
            grid_height = (ROWS * BOX_SIZE) + ((ROWS - 1) * GAP)
            start_x = (WINDOW_WIDTH - grid_width) // 2
            start_y = (WINDOW_HEIGHT - grid_height) // 2

            for r in range(ROWS):
                for c in range(COLS):
                    x = start_x + (COLS - 1 - c) * (BOX_SIZE + GAP)
                    y = start_y + r * (BOX_SIZE + GAP)

                    rect = pygame.Rect(x, y, BOX_SIZE, BOX_SIZE)


                    pygame.draw.rect(screen, colors_board[r][c], rect)

                    # Draw Letter
                    if board[r][c] != "":
                        text_surf, text_rect = font.render(board[r][c], (255, 255, 255))
                        text_rect.center = rect.center
                        screen.blit(text_surf, text_rect)
                    if r == current_row and c == current_col:
                        border_color = (255, 255, 255)
                    else:
                        border_color = (70, 70, 70)

                    pygame.draw.rect(screen, border_color, rect, 2)

            if error:
                err_surf, err_rect = font.render("המילה לא קיימת או שלא מילאת את השורה!"[::-1], (255, 0, 0), size=20)

                # Center the error message below the grid
                err_x = (WINDOW_WIDTH - err_surf.get_width()) // 2
                err_y = start_y + grid_height + 30

                screen.blit(err_surf, (err_x, err_y))
            if game_won:
                win_surf, win_rect = font.render("ניצחון!", (0, 255, 0), size=50)
                win_rect.center = (WINDOW_WIDTH // 2, 50)  # Top of screen
                screen.blit(win_surf, win_rect)
                pygame.display.flip()
                time.sleep(3)
                finish = True
            elif game_lost:
                lost_surf, lost_rect = font.render("הפסד", (255, 0, 0), size=50)
                lost_rect.center = (WINDOW_WIDTH // 2, 50)
                screen.blit(lost_surf,lost_rect)
                pygame.display.flip()
                time.sleep(3)
                finish = True
            else:
                pygame.display.flip()
            clock.tick(60)

        pygame.quit()

    def check_line(self, board, row, length):
        current_line_letters = [char for char in board[row] if char != ""]

        if len(current_line_letters) == length:
            word = "".join(board[row])
            if word in self.words[length]:
                return True
            else:
                print("The word dont exist!")
                return False
        else:
            print("Line is not full yet!")
            return False
    def load_words(self):
        try:
            with open('hebrew_words', 'rb') as f:
                data = pickle.load(f)
            return data
        except FileNotFoundError:
            print("File not found.")
            return None
        except Exception as e:
            print(f"Error loading data: {e}")
            return None

    def submit_row(self,word):
        self.client.send(const.word +":"+ word)
        color_str = self.client.wait_response()
        if color_str.startswith(const.win):
            return True
        if color_str[:5] == "color":
            color_strings = [c for c in color_str[5:].split(";") if c]
            color_list = [eval(c) for c in color_strings]
            return color_list
class button_thread(threading.Thread):
    def __init__(self, client):
        super().__init__(daemon=True)
        self.client = client

    def button_Signup(self, user, email, pw):
        self.client.send(f"SignUp:{user};{email};{pw}")
        resp = self.client.wait_response()
        return resp == "SignUpS" if resp in ("SignUpS", "SignUpF") else None

    def button_Login(self, user, password):
        self.client.send(f"Login:{user};{password}")
        return self.client.wait_response()

    def button_Logout(self):
        self.client.send("Logout:")
        resp = self.client.wait_response()
        return resp == "LogoutS"

    def email_password_check(self, password):
        self.client.send("Email:" + password)
        response = self.client.wait_response()
        return response == "EmailS"

    def button_reset_password(self, user, new_password):
        self.client.send(f"ResetPassword:{user};{new_password}")
        resp = self.client.wait_response()
        return resp == "ResetS"

    def button_forgot(self, user):
        self.client.send(f"ForgotPassword:{user}")
        return self.client.wait_response()

    def button_encrypt(self, encryption_method):
        self.client.send(encryption_method, key=True)
        worked = self.client.wait_response()
        if worked == "KeyT":
            return True
        elif worked == "KeyF":
            return False


def main():
    try:
        client = HandelCommunication()
        print("Connected to server!")
    except Exception as e:
        print(f"Failed to connect to server: {e}")
        return

    tkcu.set_default_color_theme("blue")
    app = MainApp(client)
    app.mainloop()
    client.close()


if __name__ == "__main__":
    main()