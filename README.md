letsrenew.py
============

Python3 script to automatically renew Let's Encrypt certificates.

Prerequisites
-------------

* python3
* python3-cryptography >= 0.7

Usage
-----

Typical usage:

* `./letsrenew.py --certdir /etc/nginx/certs -n`

  Show common name and days to expiry of certificates in `/etc/nginx/certs`
  ending with `.crt` (default value). Can be used in a cronjob to, for example,
  periodically email certificate expiry dates.
  
* `./letsrenew.py --certdir /etc/nginx/certs --ignore-substring chain -n`

  Show common name and days to expiry of certificates in `/etc/nginx/certs/`
  ending with `.crt` (default value), filtering filenames containing 'chain'
