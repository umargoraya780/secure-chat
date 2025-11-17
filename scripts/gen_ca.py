import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization


CERTS = Path("certs")


def create_rsa_key(bits=2048):
    """Return a new RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def write_file(path: Path, data: bytes, description: str):
    """Simple helper to store PEM files cleanly."""
    print(f"[+] Writing {description}: {path}")
    with path.open("wb") as f:
        f.write(data)


def make_ca_subject():
    """Build the distinguished name for the self-signed CA."""
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])


def build_self_signed_cert(key, name):
    """Construct and sign a self-signed CA certificate."""
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
    )

    return builder.sign(private_key=key, algorithm=hashes.SHA256())


def generate_ca_materials():
    print("\n=== Creating Root CA Materials ===")

    # 1 — Generate key
    key = create_rsa_key()
    key_path = CERTS / "ca_key.pem"
    write_file(
        key_path,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        "CA private key"
    )

    # 2 — Build subject + self-signed certificate
    subject = make_ca_subject()
    certificate = build_self_signed_cert(key, subject)

    cert_path = CERTS / "ca_cert.pem"
    write_file(
        cert_path,
        certificate.public_bytes(serialization.Encoding.PEM),
        "CA certificate"
    )

    print("[✓] Root CA successfully generated.\n")


def main():
    generate_ca_materials()


if __name__ == "__main__":
    main()
