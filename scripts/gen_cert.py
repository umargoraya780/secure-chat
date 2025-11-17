import sys
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa


CERTS_DIR = Path("certs")


def read_ca_material():
    """Load CA private key and certificate."""
    key_file = CERTS_DIR / "ca_key.pem"
    cert_file = CERTS_DIR / "ca_cert.pem"

    if not key_file.exists() or not cert_file.exists():
        print("[!] Missing CA materials.")
        print("Run: python scripts/gen_ca.py")
        sys.exit(1)

    with key_file.open("rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    with cert_file.open("rb") as f:
        ca_certificate = x509.load_pem_x509_certificate(f.read())

    return ca_key, ca_certificate


def generate_key():
    """Return a freshly generated RSA key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


def save_pem(path: Path, data: bytes, msg: str):
    """Helper to write binary data to a file."""
    print(f"[+] Writing {msg}: {path}")
    with path.open("wb") as f:
        f.write(data)


def build_subject(entity: str):
    """Create x509 subject based on entity name."""
    common = "localhost" if entity == "server" else entity

    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Entity"),
        x509.NameAttribute(NameOID.COMMON_NAME, common),
    ])


def sign_certificate(private_key, subject, ca_cert, ca_key, include_san=False):
    """Build and sign X.509 certificate."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    )

    if include_san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False
        )

    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


def issue_certificate(entity_name: str, ca_key, ca_cert):
    print(f"\n=== Generating certificate for '{entity_name}' ===")

    # 1. Key generation
    key = generate_key()
    key_path = CERTS_DIR / f"{entity_name}_key.pem"

    save_pem(
        key_path,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        "private key"
    )

    # 2. Subject + certificate
    subject = build_subject(entity_name)
    cert = sign_certificate(
        private_key=key,
        subject=subject,
        ca_cert=ca_cert,
        ca_key=ca_key,
        include_san=(entity_name == "server")
    )

    cert_path = CERTS_DIR / f"{entity_name}_cert.pem"
    save_pem(
        cert_path,
        cert.public_bytes(serialization.Encoding.PEM),
        "certificate"
    )

    print(f"[✓] Done: {entity_name}")


def main():
    ca_key, ca_cert = read_ca_material()
    issue_certificate("server", ca_key, ca_cert)
    issue_certificate("client", ca_key, ca_cert)


if __name__ == "__main__":
    main()
