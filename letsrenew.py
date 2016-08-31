#!/usr/bin/env python3

"""
letsrenew.py automates certificate renewal with Let's Encrypt.
"""

import argparse

from datetime import datetime as dt
from os import listdir
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

EXPIRY_LIMIT = 2

def days_to_expiry(certificate):
    """Get the number of days before a certificate expires"""
    return (certificate.not_valid_after - dt.utcnow()).days

def print_certificate_information(certificate):
    """Print some information about the supplied certificate"""
    common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    print("CN: " + common_name + ", expires in " + str(days_to_expiry(certificate)) + " days.")

def select_renewable_certificates(certificate_list):
    """From a certificate list, select certificates that expire in less than EXPIRY_LIMIT"""
    return [c for c in certificate_list if days_to_expiry(c) <= EXPIRY_LIMIT]

def load_certificates(file_list):
    certs = []
    for crt in file_list:
        try:
            cfile = open(crt, 'rb').read()
            cert = x509.load_pem_x509_certificate(cfile, default_backend())
        except:
            print("Loading certificate " + crt + " failed.")
        else:
            certs.append(cert)
    return certs

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

if __name__ == '__main__':
    main()

# vim: et:sw=4:ts=4:colorcolumn=100:ai:
