import sys
import threading
from AsyncMessages import AsyncMessages
from Email import email_send
from pickle import loads
from pickle import dumps
import socket
import time
import os
from sqlpy import sqlpy
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import pickle
import const
import random
__author__ = "Ben"

IP = "0.0.0.0"

PORT = 8080
SIZE_HEADER_FORMAT = "00000000|"
size_header_size = len(SIZE_HEADER_FORMAT)
TCP_DEBUG = True
LEN_TO_PRINT = 100
game_sessions = {}
async_msg = None


class HandelCommunication(threading.Thread):
    def __init__(self, cli_socket, tid, shared_sqlpy):
        super().__init__(daemon=True)
        self.cli = cli_socket
        self.tid = tid
        self.sqlpy = shared_sqlpy
        self.associated_data = b"Bentheking"
        self.method = None        # per-client, not global
        self.private_key = None   # per-client RSA private key
        self.aes_obj = None
        self.shared_key = None    # DH shared key flag
        self.current_word = ""
        self.game_id = None
    def run(self):
        global async_msg
        print("New Client num " + str(self.tid))
        exit_thread = False
        user_name = ""

        while not exit_thread:
            user_name = ""
            finished_login = False

            # login/signup loop
            while not exit_thread and not finished_login:
                data = self.recv()

                if data == "KeyT":
                    # Echo KeyT back to client
                    self.send("KeyT", key=True)
                    # Now kick off the method-specific handshake
                    if self.method == b"Diffie-Hellman":
                        try:
                            self._do_dh_handshake()
                        except Exception as e:
                            print("DH handshake error:", e)
                    # RSA: client will send "PublicKey" next, handled below

                elif data == "KeyF":
                    self.send("KeyF", key=True)

                elif data == "PublicKey":
                    self.send(self.send_rsa_public_key(), key=True)

                elif data is None:
                    # AES key was just set up — loop to get next message
                    continue

                elif data == "":
                    print("Client disconnected before login")
                    exit_thread = True
                    break

                elif data[:6] == "SignUp" and len(data) > 8:
                    fields = data[7:].split(';')
                    user_name, email, pw = fields[0], fields[1], fields[2]
                    if self.sqlpy.IsuserExixst(user_name, pw):
                        self.send("SignUpF")
                    else:
                        self.sqlpy.Saveuser(user_name, pw, email)
                        self.send("SignUpS")

                elif data[:5] == "Login" and len(data) > 7:
                    fields = data[6:].split(';')
                    user_name, pw = fields[0], fields[1]
                    if not self.sqlpy.IsuserExixst(user_name, pw):
                        self.send("LoginF")
                    elif self.sqlpy.usernotavilable(user_name):
                        self.send("LoginNotAb")
                    else:
                        async_msg.sock_by_user[user_name] = self.cli
                        self.send("LoginS")
                        self.sqlpy.setnotavilable(user_name)
                        self.sqlpy.SetEmailPassword(user_name, email_send(self.sqlpy.GetUserEmail(user_name)))
                        threading.Timer(300, self._email_timeout, args=[user_name]).start()

                elif data[0:5] == "Email":
                    try:
                        password = int(data.split(":")[1])
                        if password == self.sqlpy.GetEmailPassword(user_name):
                            self.send("EmailS")
                            finished_login = True
                            self.sqlpy.DeleteEmailPassword(user_name)
                        else:
                            self.send("EmailF")
                    except Exception:
                        self.send("EmailF")
                elif data[0:14] == "ForgotPassword":
                    user_name = data.split(":")[1]
                    if self.sqlpy.IsuserExixst_byname(user_name):
                        self.send("ForgotS")
                        self.sqlpy.SetEmailPassword(user_name, email_send(self.sqlpy.GetUserEmail(user_name)))
                        threading.Timer(300, self._email_timeout, args=[user_name]).start()
                    else:
                        self.send("ForgotF")

                if exit_thread:
                    break

            if exit_thread:
                break

            # game loop
            self.cli.settimeout(0.3)
            logged_out = False

            while not exit_thread and not logged_out:
                try:
                    data = self.recv()
                    if data == "":
                        print(f"Client {user_name} disconnected")
                        if user_name in self.sqlpy.not_avilable:
                            self.sqlpy.not_avilable.remove(user_name)
                        exit_thread = True
                        break

                    to_send = self.handle_game(data, user_name)
                    if to_send:
                        self.send(to_send)

                    if data.split(":")[0] == "Logout":
                        if user_name in async_msg.sock_by_user:
                            del async_msg.sock_by_user[user_name]
                        if user_name in self.sqlpy.not_avilable:
                            self.sqlpy.not_avilable.remove(user_name)
                        user_name = ""
                        logged_out = True
                        self.cli.settimeout(None)

                except socket.timeout:
                    msgs = async_msg.get_async_messages_to_send(self.cli)
                    for msg in msgs:
                        self.send(msg)
                    time.sleep(0.1)
                    continue

                except socket.error as err:
                    if hasattr(err, 'errno') and err.errno == 10054:
                        print(f"Error {err.errno}: Client reset by peer.")
                    else:
                        print(f"Socket error for {user_name}:", err)
                    exit_thread = True
                    break

                except Exception as err:
                    print(f"Unexpected error for {user_name}:", err)
                    exit_thread = True
                    break

        if user_name and user_name in async_msg.sock_by_user:
            del async_msg.sock_by_user[user_name]
        if user_name and user_name in self.sqlpy.not_avilable:
            self.sqlpy.not_avilable.remove(user_name)
        async_msg.delete_socket(self.cli)
        self.cli.close()
        print(f"Client {self.tid} fully disconnected")

    def _do_dh_handshake(self):
        """Run the full Diffie-Hellman handshake after KeyT is confirmed."""
        # Load or generate DH parameters
        if not os.path.exists("param_file") or os.path.getsize("param_file") == 0:
            parameters = dh.generate_parameters(generator=2, key_size=2048)
            dh_parameters_pem = parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3)
            with open("param_file", "wb") as f:
                f.write(dh_parameters_pem)
        else:
            with open("param_file", "rb") as f:
                dh_parameters_pem = f.read()
            parameters = serialization.load_pem_parameters(dh_parameters_pem)

        # Send DH parameters to client
        self.send(dh_parameters_pem, key=True)

        # Generate server private key and public key
        a = parameters.generate_private_key()
        A = a.public_key()
        A_pem = A.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        # Receive client's public key B (recv() returns raw string mid-handshake)
        B_pem = self.recv()
        if not B_pem:
            raise ValueError("Did not receive client DH public key")
        if isinstance(B_pem, bytes):
            B = serialization.load_pem_public_key(B_pem)
        else:
            B = serialization.load_pem_public_key(B_pem.encode())

        # Send our public key A to client
        self.send(A_pem, key=True)

        # Compute shared secret and derive AES key
        shared_key = a.exchange(B)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(shared_key)

        self.shared_key = derived_key

        # Receive the client's "aes:<derived_key>" confirmation
        aes_frame = self.recv()
        if isinstance(aes_frame, str):
            aes_frame = aes_frame.encode()
        if not aes_frame or not aes_frame.startswith(b"aes:"):
            raise ValueError(f"Expected aes: confirmation, got: {aes_frame[:30]}")
        self.aes_obj = AESGCM(aes_frame[4:])

        print("DH handshake complete.")

    def _email_timeout(self, user_name):
        """Called after 5 minutes — clears the email password and notifies the client."""
        if self.sqlpy.GetEmailPassword(user_name) is not None:
            self.sqlpy.DeleteEmailPassword(user_name)
            if user_name in self.sqlpy.not_avilable:
                self.sqlpy.not_avilable.remove(user_name)
            try:
                self.send("EmailTimeout")
            except Exception:
                pass

    def recv(self, buffersize=2048, flags=0):
        size_header = b''
        while len(size_header) < size_header_size:
            try:
                chunk = self.cli.recv(size_header_size - len(size_header), flags)
            except ConnectionResetError:
                return ''
            if not chunk:
                return ''
            size_header += chunk
        try:
            data_len = int(size_header[:size_header_size - 1])
        except ValueError:
            if TCP_DEBUG:
                print("Error: Invalid header received.")
            return ''
        data = b''
        while len(data) < data_len:
            chunk = self.cli.recv(data_len - len(data), flags)
            if not chunk:
                return ''
            data += chunk
        if TCP_DEBUG:
            print(f"\nRecv({data_len})>>>{data[:LEN_TO_PRINT]}")
        if data_len != len(data):
            return ''

        # Key exchange — no aes_obj yet, no method set
        if self.aes_obj is None and self.method is None:
            if data == b"RSA" or data == b"Diffie-Hellman":
                self.method = data
                return "KeyT"
            return "KeyF"

        # RSA public key request
        if data == b"PublicKey":
            return "PublicKey"

        # Encrypted AES key delivery (RSA path only)
        if data[:3] == b"aes":
            try:
                if self.private_key is not None:
                    # RSA path: decrypt the AES key with our RSA private key
                    aes = self.private_key.decrypt(
                        data[4:],
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    self.aes_obj = AESGCM(aes)
                    print("RSA: AES key received and set up successfully.")
                    return None  # signal the run() loop to continue
            except Exception as e:
                print(f"RSA AES key setup failed: {e}")
                return ""

        # Mid-handshake: method chosen but AES not set yet — return raw
        if self.aes_obj is None:
            try:
                return data.decode()
            except Exception:
                return data
        ciphertext = data[:-12]
        nonce = data[-12:]
        try:
            print(self.aes_obj.decrypt(nonce, ciphertext, self.associated_data).decode())
            return self.aes_obj.decrypt(nonce, ciphertext, self.associated_data).decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return ""

    def send_rsa_public_key(self):
        """Generate or load RSA key pair, return public key PEM bytes."""
        key_file = "private_key.pem"
        if not os.path.exists(key_file) or os.path.getsize(key_file) == 0:
            # Generate new key pair
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            pem_private = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
            )
            with open(key_file, 'wb') as f:
                f.write(pem_private)

            public_key = self.private_key.public_key()
            pem_public = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open('public_key.pem', 'wb') as f:
                f.write(pem_public)
            print("RSA keys generated and saved.")
        else:
            # Load existing keys
            with open(key_file, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=b'mypassword'
                )
            with open('public_key.pem', 'rb') as f:
                pem_public = f.read()

        return pem_public

    def send(self, bdata, flags=0, key=False):
        if type(bdata) != bytes:
            bdata = bdata.encode()
        if key:
            header_data = str(len(bdata)).zfill(size_header_size - 1).encode() + b"|"
            self.cli.send(header_data + bdata)
            if TCP_DEBUG:
                print(f"\nSent(raw {len(bdata)})>>>{bdata[:LEN_TO_PRINT]}")
        else:
            nonce = os.urandom(12)
            encode_bdata = self.aes_obj.encrypt(nonce, bdata, self.associated_data)
            header_data = str(len(encode_bdata) + len(nonce)).zfill(size_header_size - 1).encode() + b"|"
            self.cli.send(header_data + encode_bdata + nonce)
            if TCP_DEBUG:
                print(f"\nSent(enc {len(encode_bdata)})>>>{bdata[:LEN_TO_PRINT]}")

    def handle_game(self, data, user_name):
        global async_msg, game_sessions
        to_send = ""
        msg_type = data.split(":")[0]

        # Handle Room Invites and Initialization
        if len(data) > 5 and data.split(";")[0] == const.play_solo:
            self.current_word = gen_word(int(data.split(";")[1]))
            to_send = const.start_solo_game

        elif data == const.ask_for_rooms:
            av_user = []
            for name in self.sqlpy.not_avilable:
                if name != user_name:
                    av_user.append(name)
            to_send = str(av_user)

        elif msg_type == const.INVITE_REQUEST:
            parts = data.split(":")[1].split(";")
            invitee = parts[0]
            word_size = int(parts[1])
            if invitee in async_msg.sock_by_user:
                invite_msg = f"{const.INVITE_REQUEST}:{user_name};{word_size}"
                async_msg.queue_message_for_user(invitee, invite_msg)

        elif msg_type == const.INVITE_ACCEPT:
            parts = data.split(":")[1].split(";")
            inviter = parts[0]
            word_size = int(parts[1])

            # Create shared game session room
            game_id = f"{inviter}_{user_name}_{time.time()}"
            game_word = gen_word(word_size)
            game_sessions[game_id] = {
                "players": [inviter, user_name],
                "sockets": {
                    inviter: async_msg.sock_by_user.get(inviter),
                    user_name: async_msg.sock_by_user.get(user_name),
                },
                "word": game_word,
                "current_turn": 0
            }
            # Assign properties to the matching thread of the accepting player
            self.game_id = game_id
            self.current_word = game_word

            # Notify inviter side about match info (they will bind game_id on next message)
            start_msg = f"{const.START_MULTIPLAYER}:{inviter},{user_name};{word_size};{game_id}"
            async_msg.queue_message_for_user(inviter, start_msg)
            to_send = f"{const.START_MULTIPLAYER}:{inviter},{user_name};{word_size};{game_id}"

        elif msg_type == const.INVITE_REJECT:
            inviter = data.split(":")[1]
            reject_msg = f"{const.INVITE_REJECT}:{user_name}"
            async_msg.queue_message_for_user(inviter, reject_msg)
            to_send = const.INVITE_REJECT

        elif msg_type == const.word:
            # e.g., "word:GUESS;game_id_string"
            payload = data.split(":")[1]
            if ";" in payload:
                cliword = payload.split(";")[0]
                client_game_id = payload.split(";")[1]
                if not self.game_id or self.game_id != client_game_id:
                    self.game_id = client_game_id
                    if self.game_id in game_sessions:
                        self.current_word = game_sessions[self.game_id]["word"]
            else:
                cliword = payload

            game = game_sessions.get(self.game_id) if self.game_id else None
            target_word = game["word"] if game else self.current_word
            print(target_word)
            if target_word != "":

                if cliword == target_word:
                    green_colors = (str(const.green) + ";") * len(target_word)
                    to_send = const.win + ":" + target_word

                    if game:
                        other_player = game["players"][(game["players"].index(user_name) + 1) % 2]

                        async_msg.queue_message_for_user(
                            other_player,
                            f"{const.MULTIPLAYER_OPPONENT_GUESS}:{cliword};{green_colors}"
                        )
                        # Graceful end event packet invocation
                        async_msg.queue_message_for_user(
                            other_player, f"game_ended:{user_name}_won"
                        )
                        # Clean session context safely
                        if self.game_id in game_sessions:
                            del game_sessions[self.game_id]

                else:
                    color_set = ""
                    for cl, l in zip(cliword, target_word):
                        if cl == l:
                            color_set += str(const.green) + ";"
                        elif cl in target_word:
                            color_set += str(const.yellow) + ";"
                        else:
                            color_set += str(const.grey) + ";"
                    to_send = const.color + color_set

                    if game:
                        other_player = game["players"][(game["players"].index(user_name) + 1) % 2]
                        # Mirror data down to the other socket instantly
                        async_msg.queue_message_for_user(
                            other_player,
                            f"{const.MULTIPLAYER_OPPONENT_GUESS}:{cliword};{color_set}"
                        )
                        game["current_turn"] = (game["current_turn"] + 1) % 2

        return to_send

def gen_word(word_len):
    try:
        with open('hebrew_words', 'rb') as f:
            dictionary = pickle.load(f)
        return random.choice([row for row in dictionary[word_len]])
    except FileNotFoundError:
        print("File not found.")
        return None
    except Exception as e:
        print(f"Error loading data: {e}")
        return None


def main():
    global async_msg
    async_msg = AsyncMessages()
    shared_sqlpy = sqlpy()

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT))
    s.listen(4)
    print(f"Server listening on port {PORT}...")

    threads = []
    i = 1

    try:
        while True:
            cli_s, addr = s.accept()
            print(f"Connection from {addr}")
            async_msg.add_new_socket(cli_s)

            handler = HandelCommunication(cli_s, i, shared_sqlpy)
            handler.start()
            threads.append(handler)
            i += 1

    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        for t in threads:
            t.join(timeout=1)
        s.close()
        print("Bye ..")


if __name__ == "__main__":
    main()