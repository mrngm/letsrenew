#!/usr/bin/env python3

"""
letsrenew.py automates certificate renewal with Let's Encrypt.
"""

import argparse

from datetime import datetime as dt
from os import listdir
from cryptography.hazmat.backends import default_backend
from cryptography import x509


def days_to_expiry(cert_file):
    """Get the number of days before a certificate expires"""

    try:
        certificate = open(cert_file, 'rb').read()
        cert = x509.load_pem_x509_certificate(certificate, default_backend())

        now = dt.utcnow()

        return (cert.not_valid_after - now).days

    except OSError as error:
        print("OSError while trying to read file " + cert_file + ": " + error)

def main():
    """Build the argument parser and run the program"""

    parser = argparse.ArgumentParser(description=u"Automatically renew Let's Encrypt certificates")
    parser.add_argument('--certdir', metavar='CERTDIR', required=True,
                        dest='certdir', help=u'Directory where to look for certificates')
    parser.add_argument('--dry-run', '-n', default=False, action="store_true",
                        help=u'Only print certificate common name (CN) and days to expiry')
    parser.add_argument('--cert-ext', metavar='CERT_EXT', dest='cert_ext',
                        help=u'Default extension for certificate files (defaults to .crt)',
                        default='.crt')
    parser.add_argument('--ignore-substring', metavar='STR', dest='ignore_substring',
                        help=u'Ignore files containing STR', default='')
    args = parser.parse_args()

    certificates = [c for c in listdir(args.certdir) if c.endswith(args.cert_ext)]
    if args.ignore_substring != '':
        certificates = [c for c in certificates if not args.ignore_substring in c]

    print(certificates)

if __name__ == '__main__':
    main()

# vim: et:sw=4:ts=4:colorcolumn=100:ai:
