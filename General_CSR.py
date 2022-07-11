from typing import BinaryIO

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (Encoding, PrivateFormat, NoEncryption)
from cryptography.x509.oid import NameOID


def buildCSR():
    # Generating Private Key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # Storing the key in our device for safety
    file: BinaryIO
    with open('F:\LearnPyCharm\key.pem', 'wb') as file:
        file.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

    # Generating CSRequest

    country: str = input('Country Name (2 letter code) [AU]:')
    state = input('State or Province Name (full name) [Some-State]:')
    locality = input('Locality Name (eg, city) []:')
    org = input('Organization Name (eg, company) [Internet Widgits Pty Ltd]:')
    cn = input('Common Name (e.g. server FQDN or YOUR name) []:')

    CSR = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
    ])).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())   # for signing the CSR using our onw private key

    # Writing out our CSR to disk
    with open('F:\LearnPyCharm\csr.pem', 'wb') as file:
        file.write(CSR.public_bytes(Encoding.PEM))

buildCSR()
