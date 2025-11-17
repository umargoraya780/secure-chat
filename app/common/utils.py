import json
import socket
import struct

# ============================
#   Networking Helper Functions
# ============================

def send_message(sock, data):
    """
    Sends a JSON-serializable message over a socket.
    The message is length-prefixed with a 4-byte big-endian integer.
    
    Steps:
      1. JSON-encode the Python object.
      2. UTF-8 encode it into bytes.
      3. Prepend a 4-byte length prefix: struct.pack('>I', length).
      4. Send using sendall() to ensure full transmission.
    """
    try:
        json_data = json.dumps(data).encode('utf-8')
        len_prefix = struct.pack('>I', len(json_data))  # Big-endian unsigned int

        # sendall() ensures the entire payload is transmitted
        sock.sendall(len_prefix + json_data)
        return True

    except (socket.error, OverflowError, TypeError, json.JSONDecodeError) as e:
        print(f"[Network] Error sending message: {e}")
        return False


def receive_message(sock):
    """
    Receives a 4-byte length-prefixed JSON message from a socket.

    Steps:
      1. Read the 4-byte prefix → message length.
      2. Read exactly `msg_len` bytes from the socket.
      3. Decode the JSON payload into a Python dict.

    Returns:
      - Parsed JSON object (dict) on success
      - None on any error or closed connection
    """
    try:
        # --- Step 1: Read message length ---
        len_prefix = sock.recv(4)
        if not len_prefix:
            return None   # Client disconnected
        
        msg_len = struct.unpack('>I', len_prefix)[0]

        # --- Step 2: Read full message payload ---
        msg_data = b''
        while len(msg_data) < msg_len:
            chunk = sock.recv(msg_len - len(msg_data))
            if not chunk:
                return None   # Connection closed prematurely
            msg_data += chunk

        # --- Step 3: Decode JSON ---
        return json.loads(msg_data.decode('utf-8'))

    except (socket.error, struct.error, UnicodeDecodeError, json.JSONDecodeError) as e:
        print(f"[Network] Error receiving message: {e}")
        return None
