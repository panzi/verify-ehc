Verify EHC
==========

A simple Python script to decode and verify an European Health Certificate QR-code.

Note that the expiration date read from the EHC doesn't seem to be the propper
expiration date of tests or vaccinations as defined by EU or local law. In all
examples I saw it is much longer. Therefore you need to implement your own logic
with the rules defined by your government to get propper expirations dates.

Here in Austria the rules as of writing (2021-06-26) are as follows (Source:
[gesundheit.gv.at](https://www.gesundheit.gv.at/service/gruener-pass/inhalt#heading_Was_bekomme_ich_ein_Impfzertifikat_und_wie_lange_gilt_es_)):

For tests:

* Self-Test: 24 hours (though self-tests don't get an EHC)
* Antigen-Tests: 48 hours
* PCR-Tests: 72 hours

For vaccinations:

* For vaccines with 2 vacciantions:
  - 1st vaccination is valid from 22 days to 90 days after the vaccination
  - 2nd vaccination adds 180 days to that (i.e. 270 days from the 1st vaccination,
    though the date of the 1st vaccination is not included in the EHC of the 2nd
    vaccination!)
* For vaccines with only 1 vaccination (e.g. Johnson & Johnson):
  - valid from 22 days to 270 days after the vaccination
* For people recovered from COVID-19 that only need 1 vaccination:
  - valid from the day of vaccination to 270 days after

**NOTE:** These rules might be different in different countries and are subject
to change. This information is supplied without liability.

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
