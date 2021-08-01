Verify EHC
==========

A simple Python script to decode and verify an European Health Certificate QR-code.

Note that the expiration date read from the EHC doesn't seem to be the proper
expiration date of tests or vaccinations as defined by EU or local law. In all
examples I saw it is much longer. Therefore you need to implement your own logic
with the rules defined by your government to get proper expirations dates.

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

Norwegian COVID-19 Certificate
------------------------------

This script also tries to support Norwegian COVID-19 certificates, which seem
to be the same as European Health Certificates except with an `NO1:` prefix
instead of an `HC1:` prefix. Though this is untested for lack of real life
examples. See also
[this blog post](https://harrisonsand.com/posts/covid-certificates/).

Usage
-----

```plain
usage: verify_ehc.py [--help]
                     [--certs-file FILE | --certs-from LIST | --certs-table LIST]
                     [--no-verify] [--list-certs] [--print-exts]
                     [--strip-revoked] [--save-certs FILE]
                     [--download-root-cert SOURCE[@FILENAME]]
                     [--download-all-root-certs] [--allow-public-key-only]
                     [--envfile FILE] [--image]
                     [ehc_code ...]

positional arguments:
  ehc_code              Scanned EHC QR-code, or when --image is passed path to
                        an image file.

optional arguments:
  --help, -h            Show this help message and exit.
  --certs-file FILE     Trust list in CBOR or JSON format.
  --certs-from LIST     Download trust list from given country's trust list
                        service. Comma separated list, entries from later
                        country overwrites earlier.
                        See also environment variables.
                        
                        Supported countries: AT, CH, DE, FR, GB, NL, NO, SE
                        
                        Note that the GB trust list only contains GB public
                        keys, so you might want to combine it with another.
                        
                        If neither --certs-file nor --certs-from is given then
                        --certs-from=DE,AT is used as default.
                        
  --certs-table LIST    Print table of trust list certificates showing where
                        which key ID is avaliable showing the country of the
                        certificate as it is known to the given trust list. "X"
                        means the certificate/public key is in the trust list,
                        but no country attribute is known for it.
  --no-verify           Skip certificate verification.
  --list-certs          List certificates from trust list.
  --print-exts          Also print certificate extensions.
  --strip-revoked       Strip revoked certificates. (Downloads certificate
                        revocation list, if supported by certificate.)
  --save-certs FILE     Store downloaded trust list to FILE. The filetype is
                        derived from the extension, which can be .json or .cbor
  --download-root-cert SOURCE[@FILENAME]
                        Download and store root certificate (or public key) of
                        SOURCE as FILENAME. If FILENAME is not given SOURCE.pem
                        is used. If FILENAME ends in ".pem" the certificate (or
                        public key) is stored encoded as PEM, otherwise it is
                        encoded as DER.
  --download-all-root-certs
                        Download and store all root certificates (or public
                        keys) and store them in SOURCE.pem files.
  --allow-public-key-only, --allow-pubkey-only
                        When writing the CBOR trust list format it usually
                        rejects entries that are only public keys and not full
                        x509 certificates. With this options it also writes
                        entries that are only public keys.
  --envfile FILE        Load environment variables from FILE. Default is
                        ".env". Set this to an empty string to not load
                        environment varibles from a file.
  --image               ehc_code is a path to an image file containing a
                        QR-code.

environment variables:
  <SOURCE>_ROOT_CERT  Some of the trust lists are have signatures that can be
                      checked with a certain trust list specific root certificate
                      (or just public key in the case of DE). Instead of always
                      downloading these certificates you can just download them
                      once using --download-root-cert or
                      --download-all-root-certs and then supply them to this
                      script using environment variables. The environment
                      variable can be a path to a PEM or DER encoded certificate,
                      a PEM encoded public key, or the value of the environment
                      variable itself can be a PEM encoded certificate or public
                      key. You can use this to pin the root certificate.
                      
                      Example:
                        ./verify_ehc.py --download-root-cert SE@se_root_cert.crt
                        export SE_ROOT_CERT=se_root_cert.crt
                        ./verify_ehc.py --certs-from SE --save-certs certs.cbor
                      
                      Trust list sources for which root certificates are
                      supported:
                        AT, CH, DE, NL, SE

  CH_TOKEN            Downloading the Swiss (CH) trust list needs the environment
                      variable CH_TOKEN set to a bearer token that can be found
                      in the BIT's Android CovidCertificate app APK. See also:
                      https://github.com/cn-uofbasel/ch-dcc-keys

  FR_TOKEN            Downloading the French (FR) trust list needs the
                      environment variable FR_TOKEN set to a bearer token that
                      can be found in the TousAntiCovid Verif app APK.

  NO_TOKEN            Downloading the Norwegian (NO) trust list needs the
                      environment variable NO_TOKEN set to an AuthorizationHeader
                      string that can be found in the Kontroll av
                      koronasertifikat app APK. See also:
                      https://harrisonsand.com/posts/covid-certificates/

Report issues to: https://github.com/panzi/verify-ehc/issues
```

You can also use this tool to download the trust list as provided of one (or
more) of the supported countries and save it as JSON or CBOR:

```bash
./verify_ehc.py --certs-from AT --save-certs austrian_trust_list.json
```

```bash
./verify_ehc.py --certs-from AT --save-certs austrian_trust_list.cbor
```

It is also possible to save both versions at once:

```bash
./verify_ehc.py --certs-from AT \
    --save-certs austrian_trust_list.cbor \
    --save-certs austrian_trust_list.json
```

The CBOR version is in the same format as the CBOR part of the Austrian trust
list. The JSON version is in a format that is useful when used with the
WebCrypto browser API. I.e. it supplies the public keys as JSON Web Keys (JWK)
and the algorithm parameter object as needed by the WebCrypto API.

**NOTE:** Some trust list endpoints (UK, FR, NL) return only public keys instead
of full x509 certificates for some or all entries. These are supported for EHC
verification (untested because of lack of examples), but because they're no real
x509 certificates a valid time range of `1970-01-01T00:00:00+00:00` to
`9999-12-31T23:59:59.999999+00:00` is used. When using `--save-certs` with a
CBOR file these public keys are skipped and an error message is printed for
each. You can use them when saving the trust list to JSON, though, because that
itself doesn't contain a full x509 certificate.

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
