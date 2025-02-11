import socket
import json
import hashlib
from Cryptodome.Cipher import DES
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import hmac

def establish_dh_key_exchange(client_socket):
    dh_parameters_pem = client_socket.recv(4096)
    parameters = serialization.load_pem_parameters(dh_parameters_pem)
    
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.sendall(public_key_bytes)
    
    server_public_key_bytes = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)
    shared_secret = private_key.exchange(server_public_key)
    
    hkdf = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"dh key exchange")
    derived_key = hkdf.derive(shared_secret)
    key1, key2 = derived_key[:8], derived_key[8:16]
    
    verification_msg = client_socket.recv(44)
    print(f"[✔] {verification_msg.decode(errors='ignore')}")
    print("[✔] Key exchange complete. Secure DES keys derived.")
    
    encrypted_session_id = client_socket.recv(4096)
    des_cipher = DES.new(key1, DES.MODE_ECB)
    decrypted_session_id = des_cipher.decrypt(encrypted_session_id)
    
    return key1, key2, decrypted_session_id

def encrypt_message(key1, key2, session_id, message):
    des_cipher1 = DES.new(key1, DES.MODE_ECB)
    des_cipher2 = DES.new(key2, DES.MODE_ECB)
    encrypted_data = des_cipher2.encrypt(des_cipher1.encrypt(message.ljust(8).encode()))
    
    message_with_session = encrypted_data + b"::" + session_id
    hmac_obj = hmac.new(key2, message_with_session, hashlib.sha256)
    return message_with_session + b"::" + hmac_obj.digest()

def send_number(client_socket, key1, key2, session_id):
    data = input("Enter a number to send: ")
    encrypted_message = encrypt_message(key1, key2, session_id, data)
    client_socket.sendall(encrypted_message)
    print(json.dumps({"opcode": 30, "status": "Data Sent Securely"}))

def get_aggregate(client_socket, key1, key2, session_id):
    encrypted_message = encrypt_message(key1, key2, session_id, "sum")
    client_socket.sendall(encrypted_message)
    
    encrypted_sum_data_with_hmac = client_socket.recv(1024)
    encrypted_sum_data_key2, received_hmac_digest2 = encrypted_sum_data_with_hmac.split(b"::")
    
    hmac_obj2 = hmac.new(key2, encrypted_sum_data_key2, hashlib.sha256)
    if hmac_obj2.digest() != received_hmac_digest2:
        print("[❌] HMAC verification failed.")
        return
    
    des_cipher1 = DES.new(key1, DES.MODE_ECB)
    des_cipher2 = DES.new(key2, DES.MODE_ECB)
    decrypted_sum_data_key1 = des_cipher2.decrypt(encrypted_sum_data_key2)
    decrypted_sum_data = des_cipher1.decrypt(decrypted_sum_data_key1).strip()
    print(f"[✔] Aggregate from server: {decrypted_sum_data.decode()}")

def disconnect(client_socket, key1, key2, session_id):
    encrypted_message = encrypt_message(key1, key2, session_id, "exit")
    client_socket.sendall(encrypted_message)
    client_socket.close()
    print("[✔] Disconnected from server.")

def main():
    client_port = int(input("Enter the port for the client to run on: "))
    server_address = ('localhost', 8081)
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind(('localhost', client_port))
    client_socket.connect(server_address)
    
    try:
        key1, key2, session_id = establish_dh_key_exchange(client_socket)
        
        while True:
            print("\nMenu:")
            print("30: Send a number")
            print("40: Get aggregate from server")
            print("50: Disconnect")
            
            choice = input("Enter your choice: ")
            if choice == "30":
                send_number(client_socket, key1, key2, session_id)
            elif choice == "40":
                get_aggregate(client_socket, key1, key2, session_id)
            elif choice == "50":
                disconnect(client_socket, key1, key2, session_id)
                break
            else:
                print("[❌] Invalid choice. Please enter 30, 40, or 50.")
    except Exception as e:
        print(f"[❌] Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()