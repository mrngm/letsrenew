#!/usr/bin/env python3

"""
letsrenew.py automates certificate renewal with Let's Encrypt.
"""

import argparse
import subprocess

from datetime import datetime as dt
from os import listdir
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

EXPIRY_LIMIT = 2

def days_to_expiry(certificate):
    """Get the number of days before a certificate expires"""
    return (certificate.not_valid_after - dt.utcnow()).days

def cert_common_name(certificate):
    return certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

def print_certificate_information(certificate):
    """Print some information about the supplied certificate"""
    common_name = cert_common_name(certificate)
    print("CN: " + common_name + ", expires in " + str(days_to_expiry(certificate)) + " days.")

def select_renewable_certificates(certificate_list):
    """From a certificate list, select certificates that expire in less than EXPIRY_LIMIT"""
    return [c for c in certificate_list if days_to_expiry(c) <= EXPIRY_LIMIT]

def load_certificates(file_list):
    """Load certificates into cryptography.x509 format from a file list"""
    certs = []
    for crt in file_list:
        try:
            cfile = open(crt, 'rb').read()
            cert = x509.load_pem_x509_certificate(cfile, default_backend())
        except (OSError, ValueError):
            print("Loading certificate " + crt + " failed.")
        else:
            certs.append(cert)
    return certs

def build_private_key(common_name, keydir, numbits=4096, save=False):
    key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=numbits,
            backend=default_backend()
        )
    if save:
        with open(keydir + common_name + ".key", "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
    return key

def build_csr(common_name, private_key, csrdir="", save=False):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"NL"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Gelderland"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Nijmegen"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Moeilijklastig"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])).sign(private_key, hashes.SHA256(), default_backend())
    if save and csrdir != "":
        with open(csrdir + common_name + ".csr", "wb") as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM))
    return csr

def call_acme_tiny(csr_file, account_key_file, acme_dir):
    arguments = ["python",
                 "/root/acme-tiny/acme_tiny.py",
                 "--account-key", account_key_file,
                 "--csr", csr_file + ".csr",
                 "--acme-dir", acme_dir,
                 "--quiet"
                ]
    certificate_contents = ""
    try:
        certificate_contents = subprocess.check_output(arguments)
    except subprocess.CalledProcessError as ex:
        print(ex.cmd)
        print(ex.output)

    return certificate_contents

def main():
    """Build the argument parser and run the program"""

    parser = argparse.ArgumentParser(description=u"Automatically renew Let's Encrypt certificates")
    parser.add_argument('--certdir', metavar='CERTDIR', required=True,
                        dest='certdir', help=u'Directory where to look for certificates')
    parser.add_argument('--dry-run', '-n', default=False, action="store_true",
                        help=u'Only print certificate common name (CN) and days to expiry')
    parser.add_argument('--cert-ext', metavar='CERT_EXT', dest='cert_ext', default='.crt',
                        help=u'Default extension for certificate files (defaults to .crt)')
    parser.add_argument('--ignore-substring', metavar='STR', dest='ignore_substring',
                        help=u'Ignore files containing STR', default='')
    args = parser.parse_args()

    certdir = args.certdir if args.certdir.endswith('/') else args.certdir + '/'

    certificates = [certdir + c for c in listdir(certdir) if c.endswith(args.cert_ext)]
    if args.ignore_substring != '':
        certificates = [c for c in certificates if args.ignore_substring not in c]

    # load certificates
    certs = load_certificates(certificates)

    if args.dry_run:
        for crt in certs:
            print_certificate_information(crt)
        raise SystemExit

    renewable_certificates = select_renewable_certificates(certs)

    print("Renewable certificates: " + str(len(renewable_certificates)))
    for rcrt in renewable_certificates:
        print_certificate_information(rcrt)
        key = build_private_key(cert_common_name(rcrt), "/tmp/", save=True)
        csr = build_csr(cert_common_name(rcrt), key, csrdir="/tmp/", save=True)
        print(call_acme_tiny("/tmp/"+cert_common_name(rcrt), "/root/letsencrypt.key",
                       "/var/www/challenges"))

if __name__ == '__main__':
    main()

# vim: et:sw=4:ts=4:colorcolumn=100:ai:
