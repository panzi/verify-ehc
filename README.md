Verify EHC
==========

A simple Python script to decode and verify an European Health Certificate QR-code.

Usage
-----

```plain
usage: verify_ehc.py [-h] [--certs-file FILE] [--no-verify] [--image] [ehc_code ...]

positional arguments:
  ehc_code

optional arguments:
  -h, --help         show this help message and exit
  --certs-file FILE  Trust list in CBOR format. If not given it will be downloaded from the internet.
  --no-verify        Skip certificate verification.
  --image            Input is an image containing a qr-code.
```
