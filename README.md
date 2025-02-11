# Secure Client-Server Communication with Distributed Double DES (D-DDES)

## Overview

This project implements a secure multi-client-server communication system using the **Distributed Double DES (D-DDES)** cryptographic scheme. It ensures **secure key exchange, encrypted data transmission, message integrity verification**, and **server-side aggregation** of client data.

The system consists of:

- A **server** that handles multiple clients, manages session keys, decrypts and processes client data.
- **Clients** that connect to the server, securely transmit encrypted data, and retrieve aggregated results.
- **Diffie-Hellman (DH) key exchange** for secure key distribution.
- **Double DES encryption** for enhanced security.
- **HMAC verification** for data integrity.

## Features

- Secure **Diffie-Hellman Key Exchange** to derive two DES keys per client.
- **Double DES (2DES) encryption** for message confidentiality.
- **Session token-based authentication** to prevent replay attacks.
- **HMAC validation** to ensure message integrity.
- **Multi-client support** with concurrent connections.
- **Aggregated result computation** on the server.

## Files Included

- `server.py` - Implements the secure server.
- `client.py` - Implements the client.
- `README.md` - Instructions and explanation.

## Installation & Setup

### Prerequisites

Ensure you have Python 3 and the required cryptography libraries installed.

```sh
pip install pycryptodome cryptography
```

### Running the Server

1. Start the server:

```sh
python server.py
```

2. The server will listen for client connections on **localhost:8081**.
3. Type `stop` in the terminal to gracefully shut down the server.

### Running the Clients

1. Start a client:

```sh
python client.py
```

2. Enter a **unique port number** when prompted.
3. The client will automatically perform a **secure key exchange** with the server.
4. Choose an operation from the menu:
   - **Send a number (opcode 30)** → Encrypt and send data.
   - **Request aggregate (opcode 40)** → Get encrypted aggregated result.
   - **Disconnect (opcode 50)** → End session and close connection.

## How It Works

### 1️⃣ Secure Key Exchange

- The server generates **Diffie-Hellman (DH) parameters**.
- Clients use **DH key exchange** to derive two **DES keys (Key1 & Key2)**.
- A **session ID** is generated to track secure sessions.

### 2️⃣ Secure Data Transmission

- Clients encrypt data using **Double DES (2DES)** before sending it.
- **HMAC authentication** ensures integrity.
- A **session token** prevents replay attacks.

### 3️⃣ Server Processing

- Verifies **session token & HMAC**.
- Decrypts **Double DES** data.
- Computes **aggregated result** (sum of received numbers).
- Encrypts and sends **aggregated result** back to clients.

### 4️⃣ Error Handling

- **Incorrect HMAC** → Server rejects message.
- **Invalid session token** → Server disconnects the client.
- **Data tampering** → Server discards and logs the issue.

## Communication Protocol

| Opcode | Message Type     | Description                                 |
| ------ | ---------------- | ------------------------------------------- |
| 10     | KEY VERIFICATION | DH key exchange complete                    |
| 20     | SESSION TOKEN    | Server sends encrypted session token        |
| 30     | CLIENT ENC DATA  | Double DES encrypted data from client       |
| 40     | ENC AGGR RESULT  | Encrypted aggregated result sent to clients |
| 50     | DISCONNECT       | Client requests disconnection               |

## Notes

- Clients must **use unique ports** when connecting.
- Ensure **server is running** before starting clients.
- The **server handles multiple clients** concurrently using threads.

## Troubleshooting

- **Server crashes on invalid key exchange?** Ensure full **PEM key reception**.
- **HMAC verification fails?** Check if the client **uses the correct session key**.
- **Client unable to connect?** Ensure the **server is running and listening** on port 8081.

---
