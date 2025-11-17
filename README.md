# SecureChat – Encrypted Messaging System (Python)

SecureChat is a secure, certificate‑based encrypted messaging application built using Python sockets, custom PKI, and MySQL for credential storage.
It includes:

* **Server** with certificate validation
* **Client** with handshake + secure message exchange
* **Custom PKI** (root CA, issued certificates, verification)
* **Encrypted JSON‑based communication**
* **Replay‑attack and bad‑certificate protection**

---

## 📦 Project Structure

```
.
├── app/
│   ├── server/
│   │   ├── server.py
│   │   └── ...
│   ├── client/
│   │   ├── client.py
│   │   └── ...
│   ├── crypto/
│   │   ├── pki.py
│   │   └── ...
│   ├── storage/
│   │   ├── db.py
│   │   └── ...
│   └── common/
│       ├── utils.py
│       └── ...
├── certs/              # Root CA + generated certificates
├── docker/             # MySQL container setup
└── README.md
```

---

## 🐳 Database Setup (Docker)

Run a MySQL 8.0 database using Docker:

```bash
docker run -d --name securechat-db \
    -e MYSQL_ROOT_PASSWORD=rootpass \
    -e MYSQL_DATABASE=securechat \
    -e MYSQL_USER=scuser \
    -e MYSQL_PASSWORD=scpass \
    -p 3306:3306 mysql:8
```

### 🔍 Checking tables & dumping data

Enter the MySQL container:

```bash
docker exec -it securechat-db mysql -u root -p
```

Login using password:

```
rootpass
```

Check tables:

```sql
USE securechat;
SHOW TABLES;
```

Dump a table:

```bash
mysqldump -u root -p securechat > dump.sql
```

---

## ⚙️ Configuration Required

### 1️⃣ Generate certificates

Root CA + server cert + client cert must exist inside `certs/`.

Your script (`pki.py`) includes:

* `generate_root_ca()`
* `generate_server_certificate()`
* `generate_client_certificate()`

Run:

```bash
python generate_certs.py
```

This will create:

```
certs/root_ca.pem
certs/root_ca_key.pem
certs/server_cert.pem
certs/server_key.pem
certs/client_cert.pem
certs/client_key.pem
```

### 2️⃣ Update paths (if required)

In `server.py` and `client.py`:

```python
CERT_DIR = "certs/"
DB_CONFIG = {
    "user": "scuser",
    "password": "scpass",
    "host": "127.0.0.1",
    "database": "securechat"
}
```

---

## 🖥️ Running the Server

```bash
python app/server/server.py
```

You should see:

```
[Server] Listening on 0.0.0.0:5000
```

---

## 👤 Running the Client

```bash
python app/client/client.py
```

You will be prompted for:

```
Enter message: Hello Server!
```

---

## 🔌 Communication Flow (JSON Format)

### ✔️ Client → Server (ClientHello)

```json
{
  "type": "client_hello",
  "client_id": "client123",
  "certificate": "<PEM>"
}
```

### ✔️ Server → Client (ServerHello)

```json
{
  "type": "server_hello",
  "status": "ok",
  "server_certificate": "<PEM>"
}
```

### ✔️ Encrypted Message Exchange

```json
{
  "type": "message",
  "ciphertext": "<AES encrypted text>"
}
```

---

## 🧪 Sample Input / Output

### Client input:

```
Enter message: Hello Secure Server!
```

### Server output:

```
[Server] Received secure message from client123: Hello Secure Server!
```

---

## 🛑 Bad Certificate Handling

If the server receives an invalid or untrusted certificate:

### Server response:

```
[Server] Certificate validation failed
```

### Client sees:

```
[Client] Server rejected certificate – closing connection
```

---

## 🔗 GitHub Repository

👉 **Your GitHub Repo:**
(Add your link here)

```
https://github.com/<your-username>/<your-repo-name>
```

---

## 🛠️ Future Improvements

* TLS-like session resumption
* Certificate revocation list (CRL)
* Group messaging
* WebSocket version

