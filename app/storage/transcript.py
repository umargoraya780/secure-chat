import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class TranscriptLogger:
    """
    Handles secure transcript logging for message exchanges.

    For each peer, a new file is created:
        transcripts/<peer_name>_<unix_timestamp>.log

    Each logged line follows the assignment-required format:
        seqno | timestamp | ciphertext | signature | cert-fingerprint

    Transcript integrity can be verified using SHA256 over the entire log.
    """

    def __init__(self, peer_name):
        self.log_lines = []
        
        os.makedirs("transcripts", exist_ok=True)
        self.filename = f"transcripts/{peer_name}_{int(time.time())}.log"

        print(f"[Transcript] Logging enabled: {self.filename}")

    # -------------------------
    #   Logging
    # -------------------------

    def log_message(self, seqno, timestamp, ciphertext, signature, cert_fingerprint):
        """
        Appends a single log entry to both memory and file.

        Format (assignment spec):
            seqno|timestamp|ciphertext|signature|cert-fingerprint

        Args:
            seqno (int)
            timestamp (int or str)
            ciphertext (str)        Base64-encoded ciphertext
            signature (str)         Base64 RSA signature
            cert_fingerprint (str)  SHA256 fingerprint of peer's certificate
        """
        line = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{cert_fingerprint}\n"
        self.log_lines.append(line)

        try:
            with open(self.filename, "a") as f:
                f.write(line)
        except OSError as e:
            print(f"[Transcript] Error writing to file: {e}")

    # -------------------------
    #   Hashing
    # -------------------------

    def get_transcript_hash(self):
        """
        Computes SHA256 over the concatenation of all log lines.

        This gives the transcript integrity hash, as required:
            H = SHA256(line1 || line2 || ...)

        Returns:
            bytes: 32-byte SHA256 digest
        """
        full_transcript = "".join(self.log_lines)

        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(full_transcript.encode("utf-8"))
        return hasher.finalize()
