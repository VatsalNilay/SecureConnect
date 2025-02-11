import json
import hashlib
import socket
import threading
import hmac
from Cryptodome.Cipher import DES
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Generate Diffie-Hellman parameters
parameters = dh.generate_parameters(generator=2, key_size=512)
clients_data = {}
server_running = True

def establish_dh_key_exchange(client_socket):
    dh_parameters_pem = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )
    client_socket.sendall(dh_parameters_pem)
    
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    
    client_public_key_bytes = client_socket.recv(1024)
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes)
    
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.sendall(public_key_bytes)
    
    shared_secret = private_key.exchange(client_public_key)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"dh key exchange")
    derived_key = hkdf.derive(shared_secret)
    key1, key2 = derived_key[:8], derived_key[8:16]
    
    session_id = hashlib.sha256(shared_secret).hexdigest().ljust(64)[:64]
    verification_msg = json.dumps({"opcode": 10, "status": "Keys established"})
    client_socket.sendall(verification_msg.encode())
    
    cipher = DES.new(key1, DES.MODE_ECB)
    encrypted_session_id = cipher.encrypt(session_id.encode())
    client_socket.sendall(encrypted_session_id)
    
    return key1, key2, session_id

def handle_client(client_socket, client_address):
    try:
        key1, key2, session_id = establish_dh_key_exchange(client_socket)
        clients_data[client_address] = {"key1": key1, "key2": key2, "session_id": session_id, "aggregate_data": 0}
        
        while True:
            encrypted_data = client_socket.recv(1024)
            if not encrypted_data:
                break
            
            session, hmac_obj = encrypted_data.rsplit(b"::", 1)
            encrypted_msg, session_id_rcv = session.rsplit(b"::", 1)
            session_id_rcv = session_id_rcv.decode()
            
            if session_id_rcv != session_id:
                break
            
            hmac_obj1 = hmac.new(key2, session, hashlib.sha256)
            if hmac_obj1.digest() != hmac_obj:
                print(f"[❌] Invalid HMAC from {client_address}")
                continue
            
            cipher2 = DES.new(key2, DES.MODE_ECB)
            decrypted_data = cipher2.decrypt(encrypted_msg)
            cipher1 = DES.new(key1, DES.MODE_ECB)
            data = cipher1.decrypt(decrypted_data).strip().decode()
            
            if data == "sum":
                sum_data = str(clients_data[client_address]["aggregate_data"]).encode()
                encrypted_sum = cipher2.encrypt(cipher1.encrypt(sum_data.ljust(8)))
                hmac_sum = hmac.new(key2, encrypted_sum, hashlib.sha256).digest()
                client_socket.sendall(encrypted_sum + b"::" + hmac_sum)
            elif data == "exit":
                break
            else:
                try:
                    clients_data[client_address]["aggregate_data"] += float(data)
                except ValueError:
                    continue
    except Exception as e:
        pass
    finally:
        client_socket.close()


def server_command_listener(server_socket):
    global server_running
    while True:
        command = input()
        if command.strip().lower() == "stop":
            print("[✔] Stopping server...")
            server_running = False
            server_socket.close()
            try:
                temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                temp_socket.connect(('localhost', 8081))
                temp_socket.close()
            except Exception:
                pass
            
            break

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8081))
    server_socket.listen(5)
    
    threading.Thread(target=server_command_listener, args=(server_socket,), daemon=True).start()
    
    print("[✔] Server is running. Type 'stop' to terminate.")
    while server_running:
        try:
            client_socket, client_address = server_socket.accept()
            print(f"[+] Connected to {client_address}")
            threading.Thread(target=handle_client, args=(client_socket, client_address)).start()
        except OSError:
            break
    print("[✔] Server has shut down.")

if __name__ == "__main__":
    main()
