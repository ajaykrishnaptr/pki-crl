"""
Regenerates crl.crl signed by the intermediate CA.
Run this every ~25 days to keep the CRL valid.
"""
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

BASE = Path(__file__).parent


def load_cert(path):
    return x509.load_pem_x509_certificate(path.read_bytes(), default_backend())


def load_key(path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None, backend=default_backend())


inter_cert = load_cert(BASE / "inter.crt")
inter_key = load_key(BASE / "inter.key")

now = datetime.datetime.utcnow()
crl = (
    x509.CertificateRevocationListBuilder()
    .issuer_name(inter_cert.subject)
    .last_update(now)
    .next_update(now + datetime.timedelta(days=30))
    .sign(inter_key, hashes.SHA256(), default_backend())
)

crl_path = BASE / "crl.crl"
crl_path.write_bytes(crl.public_bytes(serialization.Encoding.DER))
print(f"CRL refreshed. Valid until {(now + datetime.timedelta(days=30)).strftime('%Y-%m-%d')}")
