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

* Self-Test: 24 hours (though as far as I know self-tests don't get an EHC)
* Antigen-Tests: 48 hours
* PCR-Tests: 72 hours

For vaccinations:

* For vaccines with 2 vacciantions:
  - 1st vaccination is valid starting from 22 days and ending at 90 days after
    the vaccination
  - 2nd vaccination adds 180 days to that (i.e. it's valid for 270 days from
    the 1st vaccination, though the date of the 1st vaccination is not included
    in the EHC of the 2nd vaccination!)
* For vaccines with only 1 vaccination (e.g. Johnson & Johnson):
  - valid starting from 22 days and ending at 270 days after the vaccination
* For people recovered from COVID-19 that only need 1 vaccination:
  - valid starting from the day of vaccination and ending at 270 days after

**NOTE:** These rules might be different in different countries and are subject
to change. This information is supplied without liability.

Usage
-----

```plain
usage: verify_ehc.py [-h] [--certs-file FILE | --certs-from LIST]
                     [--no-verify] [--list-certs] [--print-exts]
                     [--save-certs FILE] [--image]
                     [ehc_code ...]

positional arguments:
  ehc_code

optional arguments:
  -h, --help         show this help message and exit
  --certs-file FILE  Trust list in CBOR format. If not given it will be
                     downloaded from the internet.
  --certs-from LIST  Download trust list from given country's trust list
                     service. Entries from later country overwrites earlier.
                     Supported countries: AT, DE, SW, UK (comma separated
                     list, default: DE,AT)
  --no-verify        Skip certificate verification.
  --list-certs       List certificates from trust list.
  --print-exts       Also print certificate extensions.
  --save-certs FILE  Store downloaded certificates to FILE. The filetype is
                     derived from the extension, which can be .json or .cbor
  --image            Input is an image containing a QR-code.
```

You can also use this tool to download the trust list as provided of one (or
more) of the supported countries and save it as JSON or CBOR:

```bash
./verify_ehc.py --certs-from AT --save-certs austrian_trust_list.json
```

```bash
./verify_ehc.py --certs-from AT --save-certs austrian_trust_list.cbor
```

The CBOR version is in the same format as the Austrian trust list. The JSON
version is in a format that is useful when used with the WebCrypto browser API.
I.e. it supplies the public keys as JSON Web Keys (JWK) and the algorithm
parameter object as needed by the WebCrypto API.

MIT License
-----------

Copyright 2021 Mathias Panzenböck

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
