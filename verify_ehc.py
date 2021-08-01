#!/usr/bin/env python3

from typing import Tuple, Any, Dict, Optional, List, FrozenSet, Union, Type, Callable

import json
import sys
import zlib
import re
import os
import argparse
import codecs
import hashlib
import enum
import shutil

from os.path import splitext
from datetime import date, datetime, timedelta, timezone
from base64 import b64decode, b64encode, urlsafe_b64decode, urlsafe_b64encode

import cbor2 # type: ignore
import cose.algorithms # type: ignore
import cose.keys.curves # type: ignore
import cose.keys.keytype # type: ignore
import requests
import http.client

from lxml.html import fromstring as parse_html # type: ignore
from dateutil.parser import isoparse as parse_datetime
from jose import jwt, jws, jwk # type: ignore
from base45 import b45decode # type: ignore
from requests.exceptions import BaseHTTPError # type: ignore

from cose.headers import KID, Algorithm # type: ignore
from cose.keys import CoseKey
from cose.keys.curves import CoseCurve, P256, P384, P521
from cose.keys.keyops import VerifyOp # type: ignore
from cose.keys.keyparam import KpAlg, EC2KpX, EC2KpY, EC2KpCurve, KpKty, RSAKpN, RSAKpE, KpKeyOps # type: ignore
from cose.keys.keytype import KtyEC2, KtyRSA
from cose.messages import CoseMessage, Sign1Message # type: ignore
from cose.algorithms import Ps256, Es256

from cryptography import x509
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate, load_der_x509_crl, load_pem_x509_crl, Name, RelativeDistinguishedName, NameAttribute, Version, Extensions
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.name import _NAMEOID_TO_NAME
from cryptography.x509.oid import NameOID, ObjectIdentifier, SignatureAlgorithmOID, ExtensionOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key, load_der_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePublicNumbers, ECDSA, SECP256R1, EllipticCurve
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.bindings.openssl import binding
from cryptography.hazmat.backends.openssl.backend import backend # type: ignore
from cryptography.hazmat.bindings._openssl import ffi, lib # type: ignore

# based on: https://github.com/ehn-digital-green-development/ehn-sign-verify-python-trivial

# Digital Green Certificate Gateway API SPEC: https://eu-digital-green-certificates.github.io/dgc-gateway/#/Trust%20Lists/downloadTrustList
# But where is it hosted?

EPOCH = datetime(1970, 1, 1)

CertList = Dict[bytes, x509.Certificate]

JS_CERT_PATTERN = re.compile(r"'({[^-']*-----BEGIN[^']*)'")
ESC = re.compile(r'\\x([0-9a-fA-F][0-9a-fA-F])')
CURVE_NAME_IGNORE = re.compile(r'[-_ ]')

# https://tools.ietf.org/search/rfc4492#appendix-A
COSE_CURVES: Dict[str, Type[CoseCurve]] = {
    'secp256r1':  P256,
    'prime256v1': P256,
    'secp384r1':  P384,
    'secp521r1':  P521,
}

NIST_CURVES: Dict[str, Type[EllipticCurve]] = {
    'K-163': ec.SECT163K1,
    'B-163': ec.SECT163R2,
    'K-233': ec.SECT233K1,
    'B-233': ec.SECT233R1,
    'K-283': ec.SECT283K1,
    'B-283': ec.SECT283R1,
    'K-409': ec.SECT409K1,
    'B-409': ec.SECT409R1,
    'K-571': ec.SECT571K1,
    'B-571': ec.SECT571R1,
    'P-192': ec.SECP192R1,
    'P-224': ec.SECP224R1,
    'P-256': ec.SECP256R1,
    'P-384': ec.SECP384R1,
    'P-521': ec.SECP521R1,
}

SECG_TO_NIST_CURVES: Dict[str, str] = {curve.name: name for name, curve in NIST_CURVES.items()} # type: ignore

NAME_OIDS = {name: name_oid for name_oid, name in _NAMEOID_TO_NAME.items()}

NAME_OIDS_COVID_PASS_VERIFIER = dict(
    postalCode             = NameOID.POSTAL_CODE,
    street                 = NameOID.STREET_ADDRESS,
    organizationIdentifier = NameOID.ORGANIZATION_NAME,
    serialNumber           = NameOID.SERIAL_NUMBER,
)
NAME_OIDS_COVID_PASS_VERIFIER.update(NAME_OIDS)

for name in dir(cose.keys.curves):
    if not name.startswith('_'):
        curve = getattr(cose.keys.curves, name)
        if curve is not CoseCurve and isinstance(curve, type) and issubclass(curve, CoseCurve) and curve.fullname != 'RESERVED': # type: ignore
            name = CURVE_NAME_IGNORE.sub('', curve.fullname).lower() # type: ignore
            COSE_CURVES[name] = curve
del name, curve

PREFIX = 'HC1:'
PREFIX_NO = 'NO1:' # Norway

CLAIM_NAMES = {
    1: "Issuer",
    6: "Issued At",
    4: "Expires At",
    -260: "Health Claims",
}
DATETIME_CLAIMS = {6, 4}

# This is an old test trust list, not current! It includes test public keys too!
OLD_CERTS_URL_AT = 'https://dgc.a-sit.at/ehn/cert/listv2'
OLD_SIGNS_URL_AT = 'https://dgc.a-sit.at/ehn/cert/sigv2'

# Trust List used by Austrian greencheck app:
CERTS_URL_AT = 'https://greencheck.gv.at/api/masterdata'

CERTS_URL_AT_PROD = 'https://dgc-trust.qr.gv.at/trustlist'
SIGN_URL_AT_PROD  = 'https://dgc-trust.qr.gv.at/trustlistsig'

CERTS_URL_AT_TEST = 'https://dgc-trusttest.qr.gv.at/trustlist'
SIGN_URL_AT_TEST  = 'https://dgc-trusttest.qr.gv.at/trustlistsig'

ROOT_CERT_KEY_ID_AT = b'\xe0\x9f\xf7\x8f\x02R\x06\xb6'
# These root certs are copied from some presentation slides.
# TODO: Link a proper source here once it becomes available?
#
# TODO: keep up to date
# Not Before: Jun  2 13:46:21 2021 GMT
# Not After : Jul  2 13:46:21 2022 GMT
ROOT_CERT_AT_PROD = b'''\
-----BEGIN CERTIFICATE-----
MIIB1DCCAXmgAwIBAgIKAXnM+Z3eG2QgVzAKBggqhkjOPQQDAjBEMQswCQYDVQQG
EwJBVDEPMA0GA1UECgwGQk1TR1BLMQwwCgYDVQQFEwMwMDExFjAUBgNVBAMMDUFU
IERHQyBDU0NBIDEwHhcNMjEwNjAyMTM0NjIxWhcNMjIwNzAyMTM0NjIxWjBFMQsw
CQYDVQQGEwJBVDEPMA0GA1UECgwGQk1TR1BLMQ8wDQYDVQQFEwYwMDEwMDExFDAS
BgNVBAMMC0FUIERHQyBUTCAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEl2tm
d16CBHXwcBN0r1Uy+CmNW/b2V0BNP85y5N3JZeo/8l9ey/jIe5mol9fFcGTk9bCk
8zphVo0SreHa5aWrQKNSMFAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBRTwp6d
cDGcPUB6IwdDja/a3ncM0TAfBgNVHSMEGDAWgBQfIqwcZRYptMGYs2Nvv90Jnbt7
ezAKBggqhkjOPQQDAgNJADBGAiEAlR0x3CRuQV/zwHTd2R9WNqZMabXv5XqwHt72
qtgnjRgCIQCZHIHbCvlgg5uL8ZJQzAxLavqF2w6uUxYVrvYDj2Cqjw==
-----END CERTIFICATE-----
'''

ROOT_CERT_AT_TEST = b'''\
-----BEGIN CERTIFICATE-----
MIIB6zCCAZGgAwIBAgIKAXmEuohlRbR2qzAKBggqhkjOPQQDAjBQMQswCQYDVQQG
EwJBVDEPMA0GA1UECgwGQk1TR1BLMQowCAYDVQQLDAFRMQwwCgYDVQQFEwMwMDEx
FjAUBgNVBAMMDUFUIERHQyBDU0NBIDEwHhcNMjEwNTE5MTMwNDQ3WhcNMjIwNjE5
MTMwNDQ3WjBRMQswCQYDVQQGEwJBVDEPMA0GA1UECgwGQk1TR1BLMQowCAYDVQQL
DAFRMQ8wDQYDVQQFEwYwMDEwMDExFDASBgNVBAMMC0FUIERHQyBUTCAxMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE29KpT1eIKsy5Jx3J0xpPLW+fEBF7ma9943/j
4Z+o1TytLVok9cWjsdasWCS/zcRyAh7HBL+oyMWdFBOWENCQ76NSMFAwDgYDVR0P
AQH/BAQDAgeAMB0GA1UdDgQWBBQYmsL5sXTdMCyW4UtP5BMxq+UAVzAfBgNVHSME
GDAWgBR2sKi2xkUpGC1Cr5ehwL0hniIsJzAKBggqhkjOPQQDAgNIADBFAiBse17k
F5F43q9mRGettRDLprASrxsDO9XxUUp3ObjcWQIhALfUWnserGEPiD7Pa25tg9lj
wkrqDrMdZHZ39qb+Jf/E
-----END CERTIFICATE-----
'''

# Trust List used by German Digitaler-Impfnachweis app:
CERTS_URL_DE  = 'https://de.dscg.ubirch.com/trustList/DSC/'
PUBKEY_URL_DE = 'https://github.com/Digitaler-Impfnachweis/covpass-ios/raw/main/Certificates/PROD_RKI/CA/pubkey.pem'

# Netherlands public keys:
# (https://www.npkd.nl/csca-health.html)
# https://verifier-api.<acc/test/etc>.coronacheck.nl/v4/verifier/public_keys
# json containing a CMS (rfc5652) signature and a payload. Both base64 encoded.
# The payload is a json dictionary of the domestic and international keys. The
# later is an dictionary with the KID as a base64 encoded key and a subkjectPK
# and keyUsage array with the allowed use. Typical decode is:
# curl https://verifier-api.acc.coronacheck.nl/v4/verifier/public_keys |\
#    jq -r .payload  |\
#    base64 -d |\
#    jq .eu_keys
CERTS_URL_NL     = 'https://verifier-api.coronacheck.nl/v4/verifier/public_keys'
ROOT_CERT_URL_NL = 'http://cert.pkioverheid.nl/EVRootCA.cer'

# Keys from a French validation app (nothing official, just a hobby project by someone):
# https://github.com/lovasoa/sanipasse/blob/master/src/assets/Digital_Green_Certificate_Signing_Keys.json

# French trust list:
# This requires the environment variable FR_TOKEN to be set to a bearer token that can be found in the TousAntiCovid Verif app.
CERTS_URL_FR = 'https://portail.tacv.myservices-ingroupe.com/api/client/configuration/synchronisation/tacv'

# Sweden (JOSE encoded):
CERTS_URL_SE = 'https://dgcg.covidbevis.se/tp/trust-list'
ROOT_CERT_URL_SE = 'https://dgcg.covidbevis.se/tp/cert'
# See: https://github.com/DIGGSweden/dgc-trust/blob/main/specifications/trust-list.md

# United Kingdom trust list:
CERTS_URL_UK = 'https://covid-status.service.nhsx.nhs.uk/pubkeys/keys.json'

CERTS_URL_COVID_PASS_VERIFIER = 'https://covid-pass-verifier.com/assets/certificates.json'

# Norwegian trust list:
CERTS_URL_NO = 'https://koronakontroll.nhn.no/v2/publickey'
# Norwegian COVID-19 certificates seem to be based on the European Health Certificate but just with an 'NO1:' prefix.
# https://harrisonsand.com/posts/covid-certificates/

# Switzerland:
# See: https://github.com/cn-uofbasel/ch-dcc-keys
ROOT_CERT_URL_CH = 'https://www.bit.admin.ch/dam/bit/en/dokumente/pki/scanning_center/swiss_governmentrootcaii.crt.download.crt/swiss_governmentrootcaii.crt'
CERTS_URL_CH     = 'https://www.cc.bit.admin.ch/trust/v1/keys/list'
UPDATE_URL_CH    = 'https://www.cc.bit.admin.ch/trust/v1/keys/updates?certFormat=ANDROID'

USER_AGENT = 'Mozilla/5.0 (Windows) Firefox/90.0'

# See also this thread:
# https://github.com/eu-digital-green-certificates/dgc-participating-countries/issues/10

DEFAULT_NOT_VALID_BEFORE = datetime(1970, 1, 1, tzinfo=timezone.utc)
DEFAULT_NOT_VALID_AFTER  = datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)

class HackCertificate(x509.Certificate):
    _public_key: Union[EllipticCurvePublicKey, RSAPublicKey]
    _issuer: Name
    _subject: Name
    _extensions: Extensions
    _not_valid_before: datetime
    _not_valid_after: datetime

    def __init__(self,
        public_key: Union[EllipticCurvePublicKey, RSAPublicKey],
        issuer:  Optional[Name] = None,
        subject: Optional[Name] = None,
        not_valid_before: datetime = DEFAULT_NOT_VALID_BEFORE,
        not_valid_after:  datetime = DEFAULT_NOT_VALID_AFTER,
    ):
        self._public_key = public_key
        self._issuer  = issuer  if issuer  is not None else Name([])
        self._subject = subject if subject is not None else Name([])
        self._extensions = Extensions([])
        self._not_valid_before = not_valid_before
        self._not_valid_after  = not_valid_after

    def fingerprint(self, algorithm: hashes.HashAlgorithm) -> bytes:
        raise NotImplementedError

    @property
    def extensions(self) -> Extensions:
        return self._extensions

    @property
    def signature(self) -> bytes:
        return b''

    @property
    def tbs_certificate_bytes(self) -> bytes:
        return b''

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HackCertificate):
            return False
        return self.__as_tuple() == other.__as_tuple()

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, HackCertificate):
            return True
        return self.__as_tuple() != other.__as_tuple()

    def __as_tuple(self) -> Tuple[Union[EllipticCurvePublicKey, RSAPublicKey], Name, Name, Extensions]:
        return (self._public_key, self._issuer, self._subject, self._extensions)

    def __hash__(self) -> int:
        return hash(self.__as_tuple())

    @property
    def serial_number(self) -> int:
        return 0

    @property
    def issuer(self) -> Name:
        return self._issuer

    @property
    def subject(self) -> Name:
        return self._subject

    @property
    def version(self) -> Version:
        return Version.v1

    @property
    def signature_algorithm_oid(self) -> ObjectIdentifier:
        raise NotImplementedError

    @property
    def signature_hash_algorithm(self):
        raise NotImplementedError

    @property
    def not_valid_before(self) -> datetime:
        return self._not_valid_before

    @property
    def not_valid_after(self) -> datetime:
        return self._not_valid_after

    def public_key(self):
        return self._public_key

    def public_bytes(self, encoding: Encoding):
        raise NotImplementedError("cannot serialize certificate from public-key only")
        #return self._public_key.public_bytes(encoding, PublicFormat.SubjectPublicKeyInfo)

def json_serial(obj: Any) -> str:
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def load_ehc_certs(filename: str) -> CertList:
    with open(filename, 'rb') as stream:
        certs_cbor = stream.read()
    return load_ehc_certs_cbor(certs_cbor, filename)

def load_ehc_certs_cbor(cbor_data: bytes, source: str) -> CertList:
    certs_data = cbor2.loads(cbor_data)
    certs: CertList = {}
    for item in certs_data['c']:
        key_id = item['i']

        cert_data = item.get('c')
        if cert_data:
            cert = load_der_x509_certificate(cert_data)
            fingerprint = cert.fingerprint(hashes.SHA256())
            if key_id != fingerprint[0:8]:
                raise ValueError(f'Key ID missmatch: {key_id.hex()} != {fingerprint[0:8].hex()}')
        else:
            pubkey_data = item['k']
            pubkey = load_der_public_key(pubkey_data)

            nb = item.get('nb')
            not_valid_before = EPOCH + timedelta(seconds=nb) if nb is not None else DEFAULT_NOT_VALID_BEFORE

            na = item.get('na')
            not_valid_after = EPOCH + timedelta(seconds=na) if na is not None else DEFAULT_NOT_VALID_AFTER

            if isinstance(pubkey, (EllipticCurvePublicKey, RSAPublicKey)):
                cert = HackCertificate(pubkey, not_valid_before=not_valid_before, not_valid_after=not_valid_after)
            else:
                pubkey_type = type(pubkey)
                raise TypeError(f'unhandeled public key type: {pubkey_type.__module__}.{pubkey_type.__name__}')

        if key_id in certs:
            print_err(f'doubled key ID in {source} trust list, only using last: {format_key_id(key_id)}')

        certs[key_id] = cert

    return certs

def make_json_relative_distinguished_name(name: Name) -> Dict[str, str]:
    return {_NAMEOID_TO_NAME.get(attr.oid, attr.oid.dotted_string): attr.value
            for attr in reversed(list(name))}

def parse_json_relative_distinguished_name(name_dict: Dict[str, str]) -> Name:
    name_attrs: List[NameAttribute] = []

    for attr_type_str, attr_value in name_dict.items():
        attr_type = NAME_OIDS.get(attr_type_str) or ObjectIdentifier(attr_type_str)

        name_attrs.append(NameAttribute(attr_type, attr_value))

    return Name(name_attrs)

def load_hack_certs_json(data: bytes, source: str) -> CertList:
    certs_dict = json.loads(data)
    certs: CertList = {}

    for key_id_hex, cert_dict in certs_dict['trustList'].items():
        not_valid_before = parse_datetime(cert_dict['notValidBefore'])
        not_valid_after  = parse_datetime(cert_dict['notValidAfter'])

        issuer  = parse_json_relative_distinguished_name(cert_dict['issuer'])  if 'issuer'  in cert_dict else Name([])
        subject = parse_json_relative_distinguished_name(cert_dict['subject']) if 'subject' in cert_dict else Name([])

        pubkey_dict = cert_dict['publicKey']

        key_id = urlsafe_b64decode_ignore_padding(pubkey_dict['kid'])
        key_type = pubkey_dict['kty']

        if key_type == 'EC':
            curve_name = pubkey_dict['crv']
            curve_type = NIST_CURVES.get(curve_name)
            if not curve_type:
                raise ValueError(f'unknown elliptic curve: {curve_name!r}')
            curve = curve_type()

            x_bytes = urlsafe_b64decode_ignore_padding(pubkey_dict['x'])
            y_bytes = urlsafe_b64decode_ignore_padding(pubkey_dict['y'])
            x = int.from_bytes(x_bytes, byteorder="big", signed=False)
            y = int.from_bytes(y_bytes, byteorder="big", signed=False)

            ec_pubkey = EllipticCurvePublicNumbers(x, y, curve).public_key()
            cert = HackCertificate(ec_pubkey, issuer, subject, not_valid_before, not_valid_after)

            if key_id in certs:
                print_err(f'doubled key ID in {source} trust list, only using last: {format_key_id(key_id)}')

            certs[key_id] = cert

        elif key_type == 'RSA':
            e_bytes = urlsafe_b64decode_ignore_padding(pubkey_dict['e'])
            n_bytes = urlsafe_b64decode_ignore_padding(pubkey_dict['n'])
            e = int.from_bytes(e_bytes, byteorder="big", signed=False)
            n = int.from_bytes(n_bytes, byteorder="big", signed=False)

            rsa_pubkey = RSAPublicNumbers(e, n).public_key()
            cert = HackCertificate(rsa_pubkey, issuer, subject, not_valid_before, not_valid_after)

            if key_id in certs:
                print_err(f'doubled key ID in {source} trust list, only using last: {format_key_id(key_id)}')

            certs[key_id] = cert

        else:
            print_err(f'decoding {source} trust list: illegal key type: {key_type!r}')

    return certs

def print_err(msg: str) -> None:
    # so that errors and normal output is correctly interleaved:
    sys.stdout.flush()
    print(f'ERROR: {msg}', file=sys.stderr)

def print_warn(msg: str) -> None:
    # so that errors and normal output is correctly interleaved:
    sys.stdout.flush()
    print(f'WARNING: {msg}', file=sys.stderr)

def load_de_trust_list(data: bytes, pubkey: Optional[EllipticCurvePublicKey] = None) -> CertList:
    certs: CertList = {}

    sign_b64, body_json = data.split(b'\n', 1)
    sign = b64decode(sign_b64)
    body = json.loads(body_json)

    if pubkey is not None:
        r = int.from_bytes(sign[:len(sign)//2], byteorder="big", signed=False)
        s = int.from_bytes(sign[len(sign)//2:], byteorder="big", signed=False)

        sign_dds = encode_dss_signature(r, s)

        try:
            pubkey.verify(sign_dds, body_json, ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise ValueError(f'Invalid signature of DE trust list: {sign.hex()}')

    for cert in body['certificates']:
        key_id_b64 = cert['kid']
        key_id     = b64decode(key_id_b64)
        country    = cert['country']
        cert_type  = cert['certificateType']
        if cert_type != 'DSC':
            print_err(f'decoding DE trust list entry {key_id.hex()} / {key_id_b64}: unknown certificateType {cert_type!r} (country={country}, kid={key_id.hex()}')
            continue

        raw_data = b64decode(cert['rawData'])

        try:
            cert = load_der_x509_certificate(raw_data)
        except Exception as error:
            print_err(f'decoding DE trust list entry {key_id.hex()} / {key_id_b64}: {error}')
        else:
            fingerprint = cert.fingerprint(hashes.SHA256())
            if key_id != fingerprint[0:8]:
                raise ValueError(f'Key ID missmatch: {key_id.hex()} != {fingerprint[0:8].hex()}')

            if key_id in certs:
                print_err(f'doubled key ID in DE trust list, only using last: {format_key_id(key_id)}')

            certs[key_id] = cert

    return certs

def download_at_certs() -> CertList:
    response = requests.get(CERTS_URL_AT, headers={'User-Agent': USER_AGENT})
    response.raise_for_status()
    certs_json = json.loads(response.content)['trustList']
    certs_cbor = b64decode(certs_json['trustListContent'])
    certs_sig  = b64decode(certs_json['trustListSignature'])

    sig_msg = CoseMessage.decode(certs_sig)
    if not isinstance(sig_msg, Sign1Message):
        msg_type = type(sig_msg)
        raise TypeError(f'AT trust list: expected signature to be a Sign1 COSE message, but is: {msg_type.__module__}.{msg_type.__name__}')

    root_cert_key_id = sig_msg.phdr.get(KID) or sig_msg.uhdr[KID]
    root_cert: Optional[x509.Certificate] = None

    try:
        root_cert = get_at_root_cert(root_cert_key_id)
    except (BaseHTTPError, ValueError, KeyError) as error:
        print_err(f'AT trust list error (NOT VALIDATING): {error}')

    if root_cert:
        now = datetime.utcnow()
        if now < root_cert.not_valid_before:
            raise ValueError(f'AT trust list root certificate not yet valid: {now.isoformat()} < {root_cert.not_valid_before.isoformat()}')

        if now > root_cert.not_valid_after:
            raise ValueError(f'AT trust list root certificate already expired: {now.isoformat()} > {root_cert.not_valid_after.isoformat()}')

        sig_msg.key = cert_to_cose_key(root_cert)

        if not sig_msg.verify_signature():
            raise ValueError(f'Invalid signature of AT trust list: {sig_msg.signature.hex()}')

        sig = cbor2.loads(sig_msg.payload)
        digest = hashlib.sha256(certs_cbor).digest()

        if sig[2] != digest:
            raise ValueError(f'Invalid hash of AT trust list. expected: {sig[2].hex()}, actual: {digest.hex()}')

        created_at = EPOCH + timedelta(seconds=sig[5]) # I guess? Or "not valid before"?
        expires_at = EPOCH + timedelta(seconds=sig[4])

        if now > expires_at:
            raise ValueError(f'AT trust list already expired at {expires_at.isoformat()}')
    else:
        print_err(f'root certificate for AT trust list not found!')

    return load_ehc_certs_cbor(certs_cbor, 'AT')

def download_at_certs_new(test: bool = False, token: Optional[str] = None) -> CertList:
    # TODO: update to handle tokens once required
    #if token is None:
    #    token = os.getenv('AT_TOKEN')
    #    if token is None:
    #        raise KeyError(
    #            'Required environment variable AT_TOKEN for AT trust list is not set. '
    #            'Information about how to get a token will follow soon.')

    if test:
        certs_url = CERTS_URL_AT_TEST
        sign_url  = SIGN_URL_AT_TEST
        root_cert = get_root_cert('AT-TEST')
    else:
        certs_url = CERTS_URL_AT_PROD
        sign_url  = SIGN_URL_AT_PROD
        root_cert = get_root_cert('AT-NEW')

    response = requests.get(certs_url, headers={'User-Agent': USER_AGENT})
    #response = requests.get(certs_url, headers={
    #    'User-Agent': USER_AGENT,
    #    'Authorization': f'Bearer {token}',
    #})
    response.raise_for_status()
    certs_cbor = response.content

    response = requests.get(sign_url, headers={'User-Agent': USER_AGENT})
    #response = requests.get(sign_url, headers={
    #    'User-Agent': USER_AGENT,
    #    'Authorization': f'Bearer {token}',
    #})
    response.raise_for_status()
    certs_sig = response.content

    sig_msg = CoseMessage.decode(certs_sig)
    if not isinstance(sig_msg, Sign1Message):
        msg_type = type(sig_msg)
        raise TypeError(f'AT trust list: expected signature to be a Sign1 COSE message, but is: {msg_type.__module__}.{msg_type.__name__}')

    root_cert_key_id = sig_msg.phdr.get(KID) or sig_msg.uhdr[KID]

    key_id = root_cert.fingerprint(hashes.SHA256())[:8]
    if key_id != root_cert_key_id:
        raise ValueError(f'AT trust list root certificate key ID missmatch. {key_id.hex()} != {root_cert_key_id.hex()}')

    now = datetime.utcnow()
    if now < root_cert.not_valid_before:
        raise ValueError(f'AT trust list root certificate not yet valid: {now.isoformat()} < {root_cert.not_valid_before.isoformat()}')

    if now > root_cert.not_valid_after:
        raise ValueError(f'AT trust list root certificate already expired: {now.isoformat()} > {root_cert.not_valid_after.isoformat()}')

    sig_msg.key = cert_to_cose_key(root_cert)

    if not sig_msg.verify_signature():
        raise ValueError(f'Invalid signature of AT trust list: {sig_msg.signature.hex()}')

    sig = cbor2.loads(sig_msg.payload)
    digest = hashlib.sha256(certs_cbor).digest()

    if sig[2] != digest:
        raise ValueError(f'Invalid hash of AT trust list. expected: {sig[2].hex()}, actual: {digest.hex()}')

    created_at = EPOCH + timedelta(seconds=sig[5]) # I guess? Or "not valid before"?
    expires_at = EPOCH + timedelta(seconds=sig[4])

    if now > expires_at:
        raise ValueError(f'AT trust list already expired at {expires_at.isoformat()}')

    return load_ehc_certs_cbor(certs_cbor, 'AT')

def download_de_certs() -> CertList:
    response = requests.get(CERTS_URL_DE, headers={'User-Agent': USER_AGENT})
    response.raise_for_status()
    certs_signed_json = response.content

    pubkey: Optional[EllipticCurvePublicKey] = None
    try:
        pubkey = get_root_cert('DE').public_key() # type: ignore
    except (BaseHTTPError, ValueError) as error:
        print_err(f'DE trust list error (NOT VALIDATING): {error}')

    return load_de_trust_list(certs_signed_json, pubkey)

def download_se_certs() -> CertList:
    certs: CertList = {}
    root_cert: Optional[x509.Certificate] = None

    try:
        root_cert = get_root_cert('SE')
    except (BaseHTTPError, ValueError) as error:
        print_err(f'SE trust list error (NOT VALIDATING): {error}')

    response = requests.get(CERTS_URL_SE, headers={'User-Agent': USER_AGENT})
    response.raise_for_status()

    if root_cert is None:
        token = jwt.get_unverified_claims(response.content.decode(response.encoding or 'UTF-8'))
    else:
        token = load_jwt(response.content, root_cert, {'verify_aud': False})

    for country, country_keys in token['dsc_trust_list'].items():
        for entry in country_keys['keys']:
            key_id = b64decode(entry['kid'])
            for key_data in entry['x5c']:
                try:
                    cert = load_der_x509_certificate(b64decode_ignore_padding(key_data))
                except Exception as error:
                    print_err(f'decoding SE trust list entry {key_id.hex()} / {b64encode(key_id).decode("ASCII")}: {error}')
                else:
                    fingerprint = cert.fingerprint(hashes.SHA256())
                    if key_id != fingerprint[0:8]:
                        raise ValueError(f'Key ID missmatch: {key_id.hex()} != {fingerprint[0:8].hex()}')

                if key_id in certs:
                    print_err(f'doubled key ID in SE trust list, only using last: {format_key_id(key_id)}')

                certs[key_id] = cert

    return certs

def download_covid_pass_verifier_certs() -> CertList:
    certs: CertList = {}
    response = requests.get(CERTS_URL_COVID_PASS_VERIFIER, headers={'User-Agent': USER_AGENT})
    response.raise_for_status()
    certs_json = json.loads(response.content)
    for entry in certs_json:
        key_id   = bytes(entry['kid'])
        cert_der = bytes(entry['crt'])
        if cert_der:
            try:
                cert = load_der_x509_certificate(cert_der)
            except Exception as error:
                print_err(f'decoding covid-pass-verifier.com trust list entry {format_key_id(key_id)}: {error}')
            else:
                fingerprint = cert.fingerprint(hashes.SHA256())
                if key_id != fingerprint[0:8]:
                    raise ValueError(f'Key ID missmatch: {key_id.hex()} != {fingerprint[0:8].hex()}')

                if key_id in certs:
                    print_err(f'doubled key ID in covid-pass-verifier.com trust list, only using last: {format_key_id(key_id)}')

                certs[key_id] = cert
        else:
            iss = entry.get('iss')
            if iss:
                issuer = Name([NameAttribute(NAME_OIDS_COVID_PASS_VERIFIER.get(key) or ObjectIdentifier(key), value) for key, value in iss.items()])
            else:
                issuer = Name([])

            sub = entry.get('sub')
            if sub:
                subject = Name([NameAttribute(NAME_OIDS_COVID_PASS_VERIFIER.get(key) or ObjectIdentifier(key), value) for key, value in sub.items()])
            else:
                subject = Name([])

            pub = entry['pub']

            if 'x' in pub and 'y' in pub:
                # EC
                x_bytes = bytes(pub['x'])
                y_bytes = bytes(pub['y'])
                x = int.from_bytes(x_bytes, byteorder="big", signed=False)
                y = int.from_bytes(y_bytes, byteorder="big", signed=False)
                curve = SECP256R1()
                ec_pubkey = EllipticCurvePublicNumbers(x, y, curve).public_key()
                cert = HackCertificate(ec_pubkey, issuer, subject)

                if key_id in certs:
                    print_err(f'doubled key ID in covid-pass-verifier.com trust list, only using last: {format_key_id(key_id)}')

                certs[key_id] = cert

            elif 'n' in pub and 'e' in pub:
                # RSA
                e_bytes = bytes(pub['e'])
                n_bytes = bytes(pub['n'])
                e = int.from_bytes(e_bytes, byteorder="big", signed=False)
                n = int.from_bytes(n_bytes, byteorder="big", signed=False)
                rsa_pubkey = RSAPublicNumbers(e, n).public_key()
                cert = HackCertificate(rsa_pubkey, issuer, subject)

                if key_id in certs:
                    print_err(f'doubled key ID in covid-pass-verifier.com trust list, only using last: {format_key_id(key_id)}')

                certs[key_id] = cert

            else:
                print_err(f'decoding covid-pass-verifier.com trust list entry {format_key_id(key_id)}: no supported public key data found')
    return certs

def download_fr_certs(token: Optional[str] = None) -> CertList:
    certs: CertList = {}
    if token is None:
        token = os.getenv('FR_TOKEN')
        if token is None:
            raise KeyError(
                'Required environment variable FR_TOKEN for FR trust list is not set. '
                'You can get the value of the token from the TousAntiCovid Verif app APK.')

    response = requests.get(CERTS_URL_FR, headers={
        'User-Agent': USER_AGENT,
        'Authorization': f'Bearer {token}',
    })
    response.raise_for_status()
    certs_json = json.loads(response.content)
    for key_id_b64, cert_b64 in certs_json['certificatesDCC'].items():
        key_id = b64decode_ignore_padding(key_id_b64)
        cert_pem = b64decode(cert_b64)

        # Yes, they encode it twice!
        cert_der = b64decode(cert_pem)

        try:
            try:
                cert = load_der_x509_certificate(cert_der)
            except ValueError:
                cert = load_hack_certificate_from_der_public_key(cert_der)
                # HackCertificate.fingerprint() is not implemented

                if key_id in certs:
                    print_err(f'doubled key ID in FR trust list, only using last: {format_key_id(key_id)}')

                certs[key_id] = cert

            else:
                fingerprint = cert.fingerprint(hashes.SHA256())
                if key_id != fingerprint[0:8]:
                    raise ValueError(f'Key ID missmatch: {key_id.hex()} != {fingerprint[0:8].hex()}')

                if key_id in certs:
                    print_err(f'doubled key ID in FR trust list, only using last: {format_key_id(key_id)}')

                certs[key_id] = cert

        except Exception as error:
            print_err(f'decoding FR trust list entry {key_id.hex()} / {key_id_b64}: {error}')

    return certs

# from pkcs7_detached, except no need to re-encode and re-decode everything
# see: https://github.com/jnewbigin/pkcs7_detached/blob/master/pkcs7_detached/__init__.py
def verify_pkcs7_detached_signature(document: bytes, signature: bytes, certificate: x509.Certificate) -> bool:
    # Load the string into a bio
    bio = backend._bytes_to_bio(signature) # pylint: disable=W0212

    # Create the pkcs7 object
    pkcs7_object = lib.d2i_PKCS7_bio(bio.bio, ffi.NULL)
    if pkcs7_object == ffi.NULL:
        binding._consume_errors(lib)
        raise ValueError("Unable to parse PKCS7 data")

    # Load the specified certificate
    stack = lib.sk_X509_new_null()
    res = lib.sk_X509_push(stack, certificate._x509) # type: ignore
    binding._openssl_assert(lib, res >= 1)

    # We need a CA store, even though we don't use it
    store = lib.X509_STORE_new()
    binding._openssl_assert(lib, store != ffi.NULL)

    # Load the document into a bio
    content = backend._bytes_to_bio(document) # pylint: disable=W0212

    # If PKCS7_NOVERIFY is set the signer's certificates are not chain verified.
    # TODO: This is not good, but how to do it correctly?
    flags = lib.PKCS7_NOVERIFY

    # https://www.openssl.org/docs/man1.0.2/crypto/PKCS7_verify.html
    return lib.PKCS7_verify(pkcs7_object, stack, store, content.bio, ffi.NULL, flags) == 1

def download_nl_certs(token: Optional[str] = None) -> CertList:
    # Fetch the root certificate for the Netherlands; used to secure the
    # trust list. Non fatal error if this fails.
    root_cert: Optional[x509.Certificate] = None
    try:
        root_cert = get_root_cert('NL')
    except (BaseHTTPError, ValueError) as error:
        print_err(f'NL trust list error (NOT VALIDATING): {error}')

    certs: CertList = {}
    response = requests.get(CERTS_URL_NL, headers={'User-Agent': USER_AGENT})
    response.raise_for_status()
    certs_json = json.loads(response.content)

    payload = b64decode(certs_json['payload'])

    # Signature is a CMS (rfc5652) detached signature of the payload.
    # The certificate chain in this pkcs#7 signature rolls up to the
    # rootkey of the Kingdom of the Netherlands (https://www.pkioverheid.nl)
    #
    signature = b64decode(certs_json['signature'])

    if root_cert and not verify_pkcs7_detached_signature(payload, signature, root_cert):
        raise ValueError("Signature on the trustfile of the Netherlands (NL) did not verify against the countries National PKI root")

    payload_dict = json.loads(payload)

    # We ignore the 'nl_keys' - these are for the domestic QR codes; which are
    # privacy preserving C.L. signature based to allow for unlinkability as to
    # prevent tracking/surveilance.
    #
    for key_id_b64, pubkeys in payload_dict['eu_keys'].items():
        key_id = b64decode(key_id_b64)

        for entry in pubkeys:
            # XXX: Why is subjectPk an array? How can there be more than one key to a key ID?
            pubkey_der = b64decode(entry['subjectPk'])
            # entry['keyUsage'] is array of 't' or 'v' or 'r'
            try:
                cert = load_hack_certificate_from_der_public_key(pubkey_der)
            except Exception as error:
                print_err(f'decoding NL trust list entry {key_id.hex()} / {key_id_b64}: {error}')
            else:
                if key_id in certs:
                    print_err(f'doubled key ID in NL trust list, only using last: {format_key_id(key_id)}')

                certs[key_id] = cert
    return certs

CH_USER_AGENT = 'ch.admin.bag.covidcertificate.wallet;2.1.1;1626211804080;Android;28'

def get_ch_token() -> str:
    token = os.getenv('CH_TOKEN')
    if token is None:
        raise KeyError(
            "Required environment variable CH_TOKEN for CH trust list is not set. "
            "You can get the value of the token from the BIT's Android CovidCertificate app APK.")
    return token

def download_ch_certs(token: Optional[str] = None) -> CertList:
    if token is None:
        token = get_ch_token()

    root_cert: Optional[x509.Certificate] = None
    try:
        root_cert = get_root_cert('CH')
    except (BaseHTTPError, ValueError) as error:
        print_err(f'CH trust list error (NOT VALIDATING): {error}')

    response = requests.get(CERTS_URL_CH, headers={
        'User-Agent': CH_USER_AGENT,
        'Accept': 'application/json+jws',
        'Accept-Encoding': 'gzip',
        'Authorization': f'Bearer {token}',
    })
    response.raise_for_status()

    if root_cert is None:
        certs_token = jwt.get_unverified_claims(response.content.decode(response.encoding or 'UTF-8'))
    else:
        certs_token = load_jwt(response.content, root_cert)

    active_key_ids_b64 = certs_token['activeKeyIds']
    active_key_ids = frozenset(b64decode(key_id_b64) for key_id_b64 in active_key_ids_b64)

    response = requests.get(UPDATE_URL_CH, headers={
        'User-Agent': CH_USER_AGENT,
        'Accept': 'application/json+jws',
        'Accept-Encoding': 'gzip',
        'Authorization': f'Bearer {token}',
    })
    response.raise_for_status()
    if root_cert is None:
        update_token = jwt.get_unverified_claims(response.content.decode(response.encoding or 'UTF-8'))
    else:
        update_token = load_jwt(response.content, root_cert)
    pubkeys: List[Dict[str, Optional[str]]] = update_token['certs']

    certs: CertList = {}

    for pub in pubkeys:
        key_id = b64decode(pub['keyId']) # type: ignore
        if key_id in active_key_ids:
            alg = pub['alg']
            if alg == 'ES256':
                # EC
                x_bytes = b64decode(pub['x']) # type: ignore
                y_bytes = b64decode(pub['y']) # type: ignore
                x = int.from_bytes(x_bytes, byteorder="big", signed=False)
                y = int.from_bytes(y_bytes, byteorder="big", signed=False)
                crv: str = pub['crv'] # type: ignore
                curve = NIST_CURVES[crv]()
                ec_pubkey = EllipticCurvePublicNumbers(x, y, curve).public_key()
                cert = HackCertificate(ec_pubkey)

            elif alg == 'RS256':
                # RSA
                e_bytes = b64decode(pub['e']) # type: ignore
                n_bytes = b64decode(pub['n']) # type: ignore
                e = int.from_bytes(e_bytes, byteorder="big", signed=False)
                n = int.from_bytes(n_bytes, byteorder="big", signed=False)
                rsa_pubkey = RSAPublicNumbers(e, n).public_key()
                cert = HackCertificate(rsa_pubkey)

            else:
                print_err(f'decoding CH trust list entry {format_key_id(key_id)}: algorithm not supported: {alg!r}')

            if key_id in certs:
                print_err(f'doubled key ID in CH trust list, only using last: {format_key_id(key_id)}')

            certs[key_id] = cert

    return certs

def download_no_certs(token: Optional[str] = None) -> CertList:
    NO_USER_AGENT = 'FHICORC/38357 CFNetwork/1240.0.4 Darwin/20.5.0'

    if token is None:
        token = os.getenv('NO_TOKEN')
        if token is None:
            raise KeyError(
                "Required environment variable NO_TOKEN for NO trust list is not set. "
                "You can get the value of the token from the Kontroll av koronasertifikat app APK.")

    response = requests.get(CERTS_URL_NO, headers={
        'User-Agent': NO_USER_AGENT,
        'Authorization': token,
    })
    response.raise_for_status()

    certs: CertList = {}
    # TODO: find out if there is some sort of root cert to verify the trust list?

    certs_json = json.loads(response.content)

    for entry in certs_json:
        key_id = b64decode(entry['kid'])
        pubkey_der = b64decode(entry['publicKey'])

        cert = load_hack_certificate_from_der_public_key(pubkey_der)

        if key_id in certs:
            print_err(f'doubled key ID in NO trust list, only using last: {format_key_id(key_id)}')

        certs[key_id] = cert

    return certs

def download_gb_certs() -> CertList:
    response = requests.get(CERTS_URL_UK, headers={'User-Agent': USER_AGENT})
    response.raise_for_status()

    certs: CertList = {}
    # TODO: find out if there is some sort of root cert to verify the trust list?

    md5_b64 = response.headers.get('content-md5')
    if md5_b64 is not None:
        expected_md5 = b64decode(md5_b64)
        actual_md5   = hashlib.md5(response.content).digest()
        if expected_md5 != actual_md5:
            raise ValueError(f'MD5 sum missmatch of GB trust list: expected: {expected_md5.hex()}, actual: {actual_md5.hex()}')

    certs_json = json.loads(response.content)

    for entry in certs_json:
        key_id = b64decode(entry['kid'])
        pubkey_der = b64decode(entry['publicKey'])

        cert = load_hack_certificate_from_der_public_key(
            pubkey_der,
            Name([NameAttribute(NameOID.COUNTRY_NAME, 'GB')]),
            Name([NameAttribute(NameOID.COUNTRY_NAME, 'GB')]),
        )
        if key_id in certs:
            print_err(f'doubled key ID in GB trust list, only using last: {format_key_id(key_id)}')

        certs[key_id] = cert

    return certs

DOWNLOADERS: Dict[str, Callable[[], CertList]] = {
    'AT':              download_at_certs,     # will be 'AT-greencheck' or just removed in future
    'AT-NEW':          download_at_certs_new, # will be just 'AT' in future
    'AT-TEST': lambda: download_at_certs_new(test=True),
    'CH': download_ch_certs,
    'DE': download_de_certs,
    'FR': download_fr_certs,
    'GB': download_gb_certs,
    'NL': download_nl_certs,
    'NO': download_no_certs,
    'SE': download_se_certs,
    'UK': download_gb_certs, # alias
    'COVID-PASS-VERIFIER': download_covid_pass_verifier_certs,
}

def download_ehc_certs(sources: List[str], certs_table: Dict[str, CertList] = {}) -> CertList:
    certs: CertList = {}
    get_downloader = DOWNLOADERS.get

    for source in sources:
        source_certs = certs_table.get(source)
        if source_certs is not None:
            certs.update(source_certs)
        else:
            downloader = get_downloader(source)
            if downloader is None:
                raise ValueError(f'Unknown trust list source: {source}')

            certs.update(downloader())

    return certs

def get_at_root_cert(root_cert_key_id: bytes = ROOT_CERT_KEY_ID_AT) -> x509.Certificate:
    # TODO: Find out another place where to get the AT root certificate from.
    #       This gets it from the same server as the trust list itself, which is suboptimal.

    response = requests.get('https://greencheck.gv.at/', headers={'User-Agent': USER_AGENT})
    response.raise_for_status()

    doc = parse_html(response.content.decode(response.encoding or 'UTF-8'))

    for script in doc.xpath('//script'):
        src = script.attrib.get('src')
        if src and src.startswith('/static/js/main.') and src.endswith('.chunk.js'):
            response = requests.get(f'https://greencheck.gv.at{src}', headers={'User-Agent': USER_AGENT})
            status_code = response.status_code
            if status_code < 200 or status_code >= 300:
                print_err(f'https://greencheck.gv.at{src} {status_code} {http.client.responses.get(status_code, "")}')
            else:
                source = response.content.decode(response.encoding or 'UTF-8')
                match = JS_CERT_PATTERN.search(source)
                if match:
                    certs_pems_js = match.group(1)
                    certs_pems_js = ESC.sub(lambda match: chr(int(match[1], 16)), certs_pems_js)

                    for meta_cert_key, meta_cert_src in json.loads(certs_pems_js).items():
                        meta_cert = load_pem_x509_certificate(meta_cert_src.encode())

                        key_id = meta_cert.fingerprint(hashes.SHA256())[:8]
                        if key_id == root_cert_key_id:
                            return meta_cert

    raise KeyError(f'AT certificate with key ID {format_key_id(root_cert_key_id)} not found!')

def get_at_new_root_cert() -> x509.Certificate:
    return load_pem_x509_certificate(ROOT_CERT_AT_PROD)

def get_at_test_root_cert() -> x509.Certificate:
    return load_pem_x509_certificate(ROOT_CERT_AT_TEST)

def get_de_root_pubkey() -> EllipticCurvePublicKey:
    response = requests.get(PUBKEY_URL_DE, headers={'User-Agent': USER_AGENT})
    response.raise_for_status()
    pubkey = load_pem_public_key(response.content)

    if not isinstance(pubkey, EllipticCurvePublicKey):
        pubkey_type = type(pubkey)
        raise ValueError(f'{PUBKEY_URL_DE} is expected to be an EllipticCurvePublicKey but actually is {pubkey_type.__module__}.{pubkey_type.__name__}')

    return pubkey

def get_de_root_cert() -> x509.Certificate:
    return HackCertificate(get_de_root_pubkey())

def get_nl_root_cert() -> x509.Certificate:
    response = requests.get(ROOT_CERT_URL_NL, headers={'User-Agent': USER_AGENT})
    response.raise_for_status()
    return load_der_x509_certificate(response.content)

def get_se_root_cert() -> x509.Certificate:
    response = requests.get(ROOT_CERT_URL_SE, headers={'User-Agent': USER_AGENT})
    response.raise_for_status()
    return load_pem_x509_certificate(response.content)

def get_ch_root_cert(token: Optional[str] = None) -> x509.Certificate:
    if token is None:
        token = get_ch_token()

    response = requests.get(ROOT_CERT_URL_CH, headers={
        'User-Agent': CH_USER_AGENT,
        'Accept': 'application/json+jws',
        'Accept-Encoding': 'gzip',
        'Authorization': f'Bearer {token}',
    })
    response.raise_for_status()

    return load_pem_x509_certificate(response.content)

ROOT_CERT_DOWNLOADERS: Dict[str, Callable[[], x509.Certificate]] = {
    'AT':      get_at_root_cert,
    'AT-NEW':  get_at_new_root_cert,
    'AT-TEST': get_at_test_root_cert,
    'DE':      get_de_root_cert, # actually just a public key
    'NL':      get_nl_root_cert,
    'SE':      get_se_root_cert,
    'CH':      get_ch_root_cert,
}

def get_root_cert(source: str) -> x509.Certificate:
    envvar = f'{source.replace("-", "_")}_ROOT_CERT'
    value = os.getenv(envvar)
    if value is None:
        return ROOT_CERT_DOWNLOADERS[source]()

    if value.startswith('-----BEGIN CERTIFICATE-----'):
        return load_pem_x509_certificate(value.encode())
    elif value.startswith('-----BEGIN PUBLIC KEY-----'):
        pubkey = load_pem_public_key(value.encode())

        if not isinstance(pubkey, (EllipticCurvePublicKey, RSAPublicKey)):
            pubkey_type = type(pubkey)
            raise ValueError(f'expected EllipticCurvePublicKey or RSAPublicKey but actually got {pubkey_type.__module__}.{pubkey_type.__name__}')

        return HackCertificate(pubkey)

    with open(value, "rb") as fp:
        data = fp.read()

    if data.startswith(b'-----BEGIN CERTIFICATE-----'):
        return load_pem_x509_certificate(data)
    elif data.startswith(b'-----BEGIN PUBLIC KEY-----'):
        pubkey = load_pem_public_key(data)

        if not isinstance(pubkey, (EllipticCurvePublicKey, RSAPublicKey)):
            pubkey_type = type(pubkey)
            raise ValueError(f'expected EllipticCurvePublicKey or RSAPublicKey but actually got {pubkey_type.__module__}.{pubkey_type.__name__}')

        return HackCertificate(pubkey)
    else:
        return load_der_x509_certificate(data)

def get_default_root_cert_filename(source: str) -> str:
    envvar = f'{source.replace("-", "_")}_ROOT_CERT'
    value = os.getenv(envvar)
    if value is not None and \
            not value.startswith('-----BEGIN CERTIFICATE-----') and \
            not value.startswith('-----BEGIN PUBLIC KEY-----'):
        return value

    return f'{source}.pem'

def save_cert(cert: x509.Certificate, filename: str) -> None:
    _, ext = splitext(filename)
    ext = ext.lower()

    if ext == '.pem':
        encoding = Encoding.PEM
    else:
        encoding = Encoding.DER

    try:
        data = cert.public_bytes(encoding)
    except NotImplementedError:
        data = cert.public_key().public_bytes(encoding, PublicFormat.SubjectPublicKeyInfo)

    with open(filename, 'wb') as fp:
        fp.write(data)

def load_jwt(token: bytes, root_cert: x509.Certificate, options: Optional[Dict[str, bool]] = None) -> Dict[str, Any]:
    header = jws.get_unverified_header(token)
    trustchain = [x509.load_der_x509_certificate(b64decode(cert_b64)) for cert_b64 in header['x5c']]
    trustchain.append(root_cert)

    rsa_padding = PKCS1v15()
    for index in range(len(trustchain) - 1):
        signed_cert = trustchain[index]
        issuer_cert = trustchain[index + 1]

        pubkey = issuer_cert.public_key()
        if isinstance(pubkey, RSAPublicKey):
            pubkey.verify(
                signed_cert.signature,
                signed_cert.tbs_certificate_bytes,
                rsa_padding,
                signed_cert.signature_hash_algorithm # type: ignore
            )
        elif isinstance(pubkey, EllipticCurvePublicKey):
            pubkey.verify(
                signed_cert.signature,
                signed_cert.tbs_certificate_bytes,
                ECDSA(signed_cert.signature_hash_algorithm),
            )
        else:
            pubkey_type = type(pubkey)
            raise ValueError(f'unsupported public key type: {pubkey_type.__module__}.{pubkey_type.__name__}')

    pubkey = trustchain[0].public_key()
    sigkey: jwk.Key
    if isinstance(pubkey, RSAPublicKey):
        rsa_pn = pubkey.public_numbers()
        e = rsa_pn.e.to_bytes((rsa_pn.e.bit_length() + 7) // 8, byteorder='big')
        n = rsa_pn.n.to_bytes((rsa_pn.n.bit_length() + 7) // 8, byteorder='big')
        sigkey = jwk.construct({
            'kty': 'RSA',
            'alg': 'RS256',
            'e': b64encode(e),
            'n': b64encode(n),
        })
    elif isinstance(pubkey, EllipticCurvePublicKey):
        ec_pn = pubkey.public_numbers()
        size = pubkey.curve.key_size // 8
        x = ec_pn.x.to_bytes(size, byteorder="big")
        y = ec_pn.y.to_bytes(size, byteorder="big")
        sigkey = jwk.construct({
            'kty': 'EC',
            'alg': 'ES256',
            'crv': SECG_TO_NIST_CURVES.get(pubkey.curve.name, pubkey.curve.name),
            'x': b64encode(x),
            'y': b64encode(y),
        })
    else:
        pubkey_type = type(pubkey)
        raise ValueError(f'unsupported public key type: {pubkey_type.__module__}.{pubkey_type.__name__}')

    return jwt.decode(token, key=sigkey, options=options)

def load_hack_certificate_from_der_public_key(data: bytes,
    issuer:  Optional[Name] = None,
    subject: Optional[Name] = None,
    not_valid_before: datetime = DEFAULT_NOT_VALID_BEFORE,
    not_valid_after:  datetime = DEFAULT_NOT_VALID_AFTER,
) -> HackCertificate:
    pubkey = load_der_public_key(data)

    if isinstance(pubkey, EllipticCurvePublicKey):
        return HackCertificate(pubkey, issuer, subject, not_valid_before, not_valid_after)
    elif isinstance(pubkey, RSAPublicKey):
        return HackCertificate(pubkey, issuer, subject, not_valid_before, not_valid_after)
    else:
        pubkey_type = type(pubkey)
        raise TypeError(f'unhandeled public key type: {pubkey_type.__module__}.{pubkey_type.__name__}')

def b64decode_ignore_padding(b64str: str) -> bytes:
    return b64decode(b64str + "=" * ((4 - len(b64str) % 4) % 4))

def urlsafe_b64decode_ignore_padding(b64str: str) -> bytes:
    return urlsafe_b64decode(b64str + "=" * ((4 - len(b64str) % 4) % 4))

def decode_ehc(b45_data: str) -> CoseMessage:
    if b45_data.startswith(PREFIX):
        b45_data = b45_data[len(PREFIX):]
    elif b45_data.startswith(PREFIX_NO):
        b45_data = b45_data[len(PREFIX_NO):]

    try:
        data = b45decode(b45_data)
    except ValueError:
        print(b45_data)
        raise ValueError(f'Invalid base45 string. Try with single quotes.') from None

    if data.startswith(b'x'):
        data = zlib.decompress(data)

    msg: CoseMessage = CoseMessage.decode(data)
    return msg

def format_key_id(key_id: bytes) -> str:
    key_id_hex = key_id.hex()
    key_id_b64 = b64encode(key_id).decode("ASCII")
    if all(byte >= 0x21 and byte <= 0x7E for byte in key_id):
        return f'{key_id_hex} / {key_id_b64} / {key_id.decode("ASCII")}'

    return f'{key_id_hex} / {key_id_b64}'

def verify_ehc(msg: CoseMessage, issued_at: datetime, certs: CertList, print_exts: bool = False) -> bool:
    cose_algo = msg.phdr.get(Algorithm) or msg.uhdr.get(Algorithm)
    print(f'COSE Sig. Algo.: {cose_algo.fullname if cose_algo is not None else "N/A"}')
    if isinstance(msg, Sign1Message):
        print(f'Signature      : {b64encode(msg.signature).decode("ASCII")}')

    # TODO: warn if key_id is in uhdr (unprotected header)?
    key_id = msg.phdr.get(KID) or msg.uhdr[KID]
    print(f'Key ID         : {format_key_id(key_id)}')

    cert = certs.get(key_id) # XXX: is this correct? is it not two levels of signed certificates?
    if not cert:
        raise KeyError(f'Key ID not found in trust list: {key_id.hex()}')

    pk = cert.public_key()
    print(f'Key Type       : {type(pk).__name__.strip("_")}')
    if not isinstance(cert, HackCertificate):
        print(f'Cert Serial Nr.: {":".join("%02x" % byte for byte in cert.serial_number.to_bytes(20, byteorder="big"))}')
    print(f'Cert Issuer    : {cert.issuer.rfc4514_string()}')
    print(f'Cert Subject   : {cert.subject.rfc4514_string()}')
    print(f'Cert Version   : {cert.version.name}')
    print( 'Cert Valid In  :',
        cert.not_valid_before.isoformat() if cert.not_valid_before is not None else 'N/A', '-',
        cert.not_valid_after.isoformat()  if cert.not_valid_after  is not None else 'N/A')

    cert_expired = False
    if cert.not_valid_before is not None and issued_at < cert.not_valid_before:
        cert_expired = True

    if cert.not_valid_after is not None and issued_at > cert.not_valid_after:
        cert_expired = True

    print(f'Cert Expired   : {cert_expired}')
    revoked_cert = get_revoked_cert(cert)
    if revoked_cert:
        print( 'Cert Revoked At:', revoked_cert.revocation_date.isoformat())
        revoked = True
    else:
        revoked = False

    if not isinstance(cert, HackCertificate):
        signature_algorithm_oid = cert.signature_algorithm_oid
        print(f'Signature Algo.: oid={signature_algorithm_oid.dotted_string}, name={signature_algorithm_oid._name}')
        print( 'Cert Signature :', b64encode(cert.signature).decode('ASCII'))

    if isinstance(pk, EllipticCurvePublicKey):
        print(f'Curve          : {pk.curve.name}')

    msg.key = cert_to_cose_key(cert)

    valid = msg.verify_signature()

    print(f'Signature Valid: {valid}')

    if print_exts and cert.extensions:
        print('Extensions     :')
        for ext in cert.extensions:
            print(f'- oid={ext.oid.dotted_string}, name={ext.oid._name}, value={ext.value}')

    return valid and not cert_expired and not revoked

def cert_to_cose_key(cert: x509.Certificate) -> CoseKey:
    pk = cert.public_key()
    if isinstance(pk, EllipticCurvePublicKey):
        ec_pn = pk.public_numbers()
        size = pk.curve.key_size // 8

        x = ec_pn.x.to_bytes(size, byteorder="big")
        y = ec_pn.y.to_bytes(size, byteorder="big")

        curve_name = CURVE_NAME_IGNORE.sub('', pk.curve.name).lower()
        curve = COSE_CURVES.get(curve_name)

        if not curve:
            raise KeyError(f'Unsupported curve: {pk.curve.name}')

        return CoseKey.from_dict(
            {
                KpKeyOps: [VerifyOp],
                KpKty: KtyEC2,
                EC2KpCurve: curve,
                KpAlg: Es256,
                EC2KpX: x,
                EC2KpY: y,
            }
        )
    elif isinstance(pk, RSAPublicKey):
        rsa_pn = pk.public_numbers()
        e = rsa_pn.e.to_bytes((rsa_pn.e.bit_length() + 7) // 8, byteorder='big')
        n = rsa_pn.n.to_bytes((rsa_pn.n.bit_length() + 7) // 8, byteorder='big')

        return CoseKey.from_dict(
            {
                KpKeyOps: [VerifyOp],
                KpKty: KtyRSA,
                KpAlg: Ps256,
                RSAKpE: e,
                RSAKpN: n,
            }
        )
    #elif isinstance(pk, DSAPublicKey):
    #    dsa_pn = pk.public_numbers()
    #    return CoseKey.from_dict(
    #        {
    #            # ???
    #        }
    #    )
    else:
        raise KeyError(f'Unsupported public key type: {type(pk).__name__}')

crl_status: Dict[str, int] = {}
crls: Dict[str, x509.CertificateRevocationList] = {}

def get_cached_crl(uri: str) -> x509.CertificateRevocationList:
    crl = crls.get(uri)

    if crl is not None:
        return crl

    status_code = crl_status.get(uri)
    if status_code is not None:
        raise ValueError(f'{uri} {status_code} {http.client.responses.get(status_code, "")}')

    response = requests.get(uri, headers={'User-Agent': USER_AGENT})
    status_code = response.status_code
    crl_status[uri] = status_code

    if response.status_code >= 400 and response.status_code < 600:
        raise ValueError(f'{uri} {status_code} {http.client.responses.get(status_code, "")}')

    crl_bytes = response.content
    if crl_bytes.startswith(b'-----BEGIN'):
        crl = load_pem_x509_crl(crl_bytes)
    else:
        crl = load_der_x509_crl(crl_bytes)

    crls[uri] = crl
    return crl

def get_revoked_cert(cert: x509.Certificate) -> Optional[x509.RevokedCertificate]:
    try:
        crl_points_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
    except ExtensionNotFound:
        pass
    else:
        crl_points = crl_points_ext.value
        for crl_point in crl_points:
            uris = crl_point.full_name
            if uris:
                for uri in uris:
                    lower_uri = uri.value.lower()
                    if lower_uri.startswith('http:') or lower_uri.startswith('https:'):
                        try:
                            crl = get_cached_crl(uri.value)
                        except Exception as error:
                            print_err(f'loading revokation list {uri.value} {error}')
                        else:
                            return crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    return None

ENV_COMMENT = re.compile(r'^\s*(?:#.*)?$')
ENV_VAR     = re.compile(r'^\s*(?P<key>[0-9_a-zA-Z]+)\s*=\s*(?:"(?P<quoted>(?:[^"\\]|\\["nrt\\])*)"\s*|(?P<plain>[^#"]*))(?:#.*)?$')
ENV_QUOTE   = re.compile(r'\\(.)')
ENV_ESC = {
    '\\': '\\',
    '"': '"',
    'n': '\n',
    'r': '\r',
    't': '\t',
}

def parse_env(data: str) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for index, line in enumerate(data.split('\n')):
        if not ENV_COMMENT.match(line):
            match = ENV_VAR.match(line)

            if not match:
                raise SyntaxError(f'in .env file: {line}')

            key: str = match.group('key') # type: ignore
            quoted: Optional[str] = match.group('quoted')
            value: str
            if quoted is not None:
                value = ENV_QUOTE.sub(lambda m: ENV_ESC[m.group(1)], quoted) # type: ignore
            else:
                value = match.group('plain') # type: ignore
            env[key] = value
    return env

def save_certs(certs: CertList, certs_path: str, allow_public_key_only: bool = False) -> None:
    ext = splitext(certs_path)[1]
    lower_ext = ext.lower()
    if lower_ext == '.json':
        from jwcrypto.jwk import JWK # type: ignore

        # JSON that includes all info in a format as needed by WebCrypto, I hope
        certs_json = {}
        for key_id, cert in certs.items():
            pubkey = cert.public_key()
            pubkey_jwk = JWK.from_pyca(pubkey)
            pubkey_json = pubkey_jwk.export(as_dict=True, private_key=False)
            pubkey_json['key_ops'] = ['verify']

            # not sure about this:
            pubkey_json['kid'] = urlsafe_b64encode(key_id).decode('ASCII')

            # even less sure about this:
            if pubkey_json['kty'] == 'EC':
                algo = {
                    'name': 'ECDSA',
                    'namedCurve': pubkey_json['crv'],
                    'hash': {'name': "SHA-256"},
                }
            else:
                algo = {
                    'name': 'RSASSA-PKCS1-v1_5',
                    'hash': {'name': "SHA-256"},
                }

            cert_json = {
                'issuer':  make_json_relative_distinguished_name(cert.issuer),
                'subject': make_json_relative_distinguished_name(cert.subject),
                'notValidBefore': cert.not_valid_before.isoformat(),
                'notValidAfter':  cert.not_valid_after.isoformat(),
                'publicKey': pubkey_json,
                'algorithm': algo,
            }

            certs_json[key_id.hex()] = cert_json

        json_doc = {
            'timestamp': datetime.utcnow().isoformat()+'Z',
            'trustList': certs_json,
        }

        with open(certs_path, 'w') as text_stream:
            json.dump(json_doc, text_stream)

    elif lower_ext == '.cbor':
        # same CBOR format as AT trust list
        cert_list: List[dict] = []
        for key_id, cert in certs.items():
            if allow_public_key_only and isinstance(cert, HackCertificate):
                entry = {
                    'k': cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
                }

                not_valid_before = cert.not_valid_before
                if not_valid_before is not DEFAULT_NOT_VALID_BEFORE:
                    entry['nb'] = int(not_valid_before.timestamp())

                not_valid_after = cert.not_valid_before
                if not_valid_after is not DEFAULT_NOT_VALID_AFTER:
                    entry['na'] = int(not_valid_after.timestamp())

                cert_list.append(entry)
            else:
                try:
                    cert_bytes = cert.public_bytes(Encoding.DER)
                except NotImplementedError as error:
                    print_err(f'Cannot store entry {key_id.hex()} / {b64encode(key_id).decode("ASCII")} in CBOR trust list: {error}')
                else:
                    cert_list.append({
                        'i': key_id,
                        'c': cert_bytes,
                    })
        with open(certs_path, 'wb') as fp:
            cbor2.dump({'c': cert_list}, fp)
    else:
        raise ValueError(f'Unsupported certificates file extension: {ext!r}')

def split_lines(text: str, width: int) -> List[str]:
    lines: List[str] = []
    for line_str in text.split('\n'):
        line: List[str] = []
        line_len = 0
        for word in line_str.split(' '):
            word_len = len(word)
            next_len = line_len + word_len
            if line: next_len += 1
            if next_len > width:
                lines.append(' '.join(line))
                line.clear()
                line_len = 0
            elif line:
                line_len += 1

            line.append(word)
            line_len += word_len

        lines.append(' '.join(line))
    return lines

def fill_text(text: str, width: int, indent: str) -> str:
    return '\n'.join(indent + line for line in split_lines(text, width - len(indent)))

class SmartFormatter(argparse.HelpFormatter):
    def _split_lines(self, text: str, width: int) -> List[str]:
        return split_lines(text, width)

    def _fill_text(self, text: str, width: int, indent: str) -> str:
        return fill_text(text, width, indent)

def parse_sources(sources_str: str) -> List[str]:
    sources_str = sources_str.strip()
    return [country.strip().upper() for country in sources_str.split(',')] if sources_str else []

class Align(enum.Enum):
    Left   = 0
    Right  = 1
    Center = 2

    def align(self, text: str, width: int, fillchar: str = ' ') -> str:
        if self == Align.Left:
            return text.ljust(width, fillchar)

        elif self == Align.Right:
            return text.rjust(width, fillchar)

        else:
            return text.center(width, fillchar)

def print_table(header: List[str], align: List[Align], body: List[List[str]]) -> None:
    widths: List[int] = [len(cell) for cell in header]

    for row in body:
        for index, cell in enumerate(row):
            cell_len = len(cell)
            while index >= len(widths):
                widths.append(0)

            if widths[index] < cell_len:
                widths[index] = cell_len

    while len(align) < len(widths):
        align.append(Align.Left)

    print(' | '.join(alignment.align(cell, width) for alignment, cell, width in zip(align, header, widths)).rstrip())
    print('-+-'.join(alignment.align('', width, '-') for alignment, width in zip(align, widths)))

    for row in body:
        print(' | '.join(alignment.align(cell, width) for alignment, cell, width in zip(align, row, widths)).rstrip())

def main() -> None:
    ap = argparse.ArgumentParser(formatter_class=SmartFormatter, add_help=False)

    ap.add_argument('--help', '-h', action='store_true', default=False, help=
        'Show this help message and exit.')

    certs_ap = ap.add_mutually_exclusive_group()

    certs_ap.add_argument('--certs-file', metavar="FILE", help=
        'Trust list in CBOR or JSON format.')

    certs_ap.add_argument('--certs-from', metavar="LIST", help=
        "Download trust list from given country's trust list service. Comma separated list, entries from later country overwrites earlier.\n"
        "See also environment variables.\n"
        "\n"
        "Supported countries: AT, CH, DE, FR, GB, NL, NO, SE\n"
        "\n"
        "Note that the GB trust list only contains GB public keys, so you might want to combine it with another.\n"
        "\n"
        "If neither --certs-file nor --certs-from is given then --certs-from=DE,AT is used as default.\n",
        default='DE,AT')

    certs_ap.add_argument('--certs-table', metavar='LIST', help=
        'Print table of trust list certificates showing where which key ID is avaliable showing the country of the certificate as it is known to the given trust list. '
        '"X" means the certificate/public key is in the trust list, but no country attribute is known for it.')

    ap.add_argument('--no-verify', action='store_true', default=False, help='Skip certificate verification.')

    ap.add_argument('--list-certs', action='store_true', help='List certificates from trust list.')
    ap.add_argument('--print-exts', action='store_true', help='Also print certificate extensions.')

    ap.add_argument('--strip-revoked', action='store_true', help=
        'Strip revoked certificates. (Downloads certificate revocation list, if supported by certificate.)')

    ap.add_argument('--save-certs', metavar='FILE', action='append', help=
        'Store downloaded trust list to FILE. The filetype is derived from the extension, which can be .json or .cbor')

    ap.add_argument('--download-root-cert', metavar='SOURCE[@FILENAME]', action='append', help=
        'Download and store root certificate (or public key) of SOURCE as FILENAME. '
        'If FILENAME is not given SOURCE.pem is used. '
        'If FILENAME ends in ".pem" the certificate (or public key) is stored encoded as PEM, otherwise it is encoded as DER.')

    ap.add_argument('--download-all-root-certs', action='store_true', help=
        'Download and store all root certificates (or public keys) and store them in SOURCE.pem files.')

    ap.add_argument('--allow-public-key-only', '--allow-pubkey-only', action='store_true', help=
        'When writing the CBOR trust list format it usually rejects entries that are only public keys and not full x509 certificates. '
        'With this options it also writes entries that are only public keys.')

    ap.add_argument('--envfile', metavar='FILE', default='.env', help=
        'Load environment variables from FILE. Default is ".env". '
        'Set this to an empty string to not load environment varibles from a file.')

    ap.add_argument('--image', action='store_true', default=False, help='ehc_code is a path to an image file containing a QR-code.')
    ap.add_argument('ehc_code', nargs='*', help='Scanned EHC QR-code, or when --image is passed path to an image file.')

    args = ap.parse_args()

    if args.help:
        width = shutil.get_terminal_size().columns

        extra_help: List[Tuple[str, List[Tuple[str, str]]]] = [
            (
                'environment variables:',
                [
                    (
                        '<SOURCE>_ROOT_CERT',
                        "Some of the trust lists are have signatures that can be checked with a certain trust list "
                        "specific root certificate (or just public key in the case of DE). Instead of always downloading "
                        "these certificates you can just download them once using --download-root-cert or "
                        "--download-all-root-certs and then supply them to this script using environment variables. "
                        "The environment variable can be a path to a PEM or DER encoded certificate, a PEM encoded "
                        "public key, or the value of the environment variable itself can be a PEM encoded certificate "
                        "or public key. You can use this to pin the root certificate.\n"
                        "\n"
                        "Example:\n"
                        "  ./verify_ehc.py --download-root-cert SE@se_root_cert.crt\n"
                        "  export SE_ROOT_CERT=se_root_cert.crt\n"
                        "  ./verify_ehc.py --certs-from SE --save-certs certs.cbor\n"
                        "\n"
                        "Trust list sources for which root certificates are supported:\n"
                        "  AT, CH, DE, NL, SE"
                    ),
                    # TODO: Write proper help text once this information becomes available.
                    #(
                    #    'AT_TOKEN',
                    #    "Downloading the Austrian (AT) trust list needs the nevironment variable AT_TOKEN set to "
                    #    "a token that you will be able to get from somewhere. Still waiting on the government to "
                    #    "pulicise anything about that.\n"
                    #    "<insert description and link here>"
                    #),
                    (
                        'CH_TOKEN',
                        "Downloading the Swiss (CH) trust list and root certificate needs the environment variable "
                        "CH_TOKEN set to a bearer token that can be found in the BIT's Android CovidCertificate app "
                        "APK. See also: https://github.com/cn-uofbasel/ch-dcc-keys"
                    ),
                    (
                        'FR_TOKEN',
                        "Downloading the French (FR) trust list needs the environment variable FR_TOKEN set to a bearer "
                        "token that can be found in the TousAntiCovid Verif app APK."
                    ),
                    (
                        'NO_TOKEN',
                        "Downloading the Norwegian (NO) trust list needs the environment variable NO_TOKEN set to an "
                        "AuthorizationHeader string that can be found in the Kontroll av koronasertifikat app APK. "
                        "See also: https://harrisonsand.com/posts/covid-certificates/"
                    ),
                ]
            )
        ]

        ap.print_help()
        print()

        item_name_limit = 20
        for title, help_items in extra_help:
            print(title)

            max_item_name_len = 0
            for item_name, description in help_items:
                item_name_len = len(item_name)
                if item_name_len > max_item_name_len and item_name_len < item_name_limit:
                    max_item_name_len = item_name_len

            if max_item_name_len == 0:
                max_item_name_len = item_name_limit

            rest_width = max(width - 4 - max_item_name_len, 1)
            indent = ' ' * (width - rest_width)
            for item_name, description in help_items:
                lines = split_lines(description, rest_width)
                if len(item_name) > item_name_limit:
                    print(f'  {item_name}')
                else:
                    print(f'  {item_name.ljust(max_item_name_len)}  {lines[0]}')
                    lines = lines[1:]

                for line in lines:
                    print(indent + line)
                print()
        print('Report issues to: https://github.com/panzi/verify-ehc/issues')

        return

    if args.envfile:
        try:
            with open(args.envfile, 'r') as text_stream:
                env_str = text_stream.read()
        except (FileNotFoundError, IsADirectoryError):
            pass
        else:
            env = parse_env(env_str)
            os.environ.update(env)

    download_root_certs = args.download_root_cert or []
    if args.download_all_root_certs:
        download_root_certs.extend(ROOT_CERT_DOWNLOADERS.keys())

    for download_root_cert in download_root_certs:
        parts = download_root_cert.split('@', 1)
        source = parts[0]
        if len(parts) > 1:
            filename = parts[1]
        else:
            filename = get_default_root_cert_filename(source)

        source_upper = source.strip().upper()
        root_cert_downloader = ROOT_CERT_DOWNLOADERS.get(source_upper)
        if root_cert_downloader is None:
            if source_upper in DOWNLOADERS:
                raise KeyError(f'{source_upper} has no known root certificate')
            else:
                raise KeyError(f'Unknown trust list source: {source}')
        root_cert = root_cert_downloader()

        save_cert(root_cert, filename)

    certs_table: Dict[str, CertList] = {}
    if args.certs_table:
        sources = parse_sources(args.certs_table)
        all_certs: CertList = {}
        get_downloader = DOWNLOADERS.get

        header: List[str] = ['Key ID']
        align: List[Align] = [Align.Left]

        for source in sources:
            header.append(source)
            align.append(Align.Center)
            downloader = get_downloader(source)
            if downloader is None:
                raise ValueError(f'Unknown trust list source: {source}')

            source_certs = downloader()
            certs_table[source] = source_certs
            all_certs.update(source_certs)

        def sort_key(key_id: bytes) -> Tuple[List[str], bytes]:
            countries: List[str] = []
            for source in sources:
                cert = certs_table[source].get(key_id)
                if cert is not None:
                    for attr in cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME):
                        countries.append(attr.value)
            return countries, key_id

        body: List[List[str]] = []
        for key_id in sorted(all_certs, key=sort_key):
            row: List[str] = [b64encode(key_id).decode('ASCII')]
            for source in sources:
                cert = certs_table[source].get(key_id)
                if cert is None:
                    cell = ''
                else:
                    cell = ','.join(attr.value for attr in cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)) or 'X'

                row.append(cell)
            body.append(row)

        print_table(header, align, body)

    certs: Optional[CertList] = None
    if not args.no_verify or args.save_certs or args.list_certs:
        if args.certs_file:
            if args.certs_file.lower().endswith('.json'):
                with open(args.certs_file, 'rb') as fp:
                    certs_data = fp.read()
                certs = load_hack_certs_json(certs_data, args.certs_file)
            else:
                certs = load_ehc_certs(args.certs_file)
        else:
            certs = download_ehc_certs(parse_sources(args.certs_from), certs_table)

        if not certs:
            print_err("empty trust list!")

        items: List[Tuple[bytes, x509.Certificate]]
        revoked_certs: Dict[bytes, x509.RevokedCertificate] = {}
        if args.list_certs or args.strip_revoked:
            items = list(certs.items())
            items.sort(key=lambda item: (item[1].issuer.rfc4514_string(), item[1].subject.rfc4514_string(), item[0]))

        if args.strip_revoked:
            for key_id, cert in items:
                revoked_cert = get_revoked_cert(cert)
                if revoked_cert:
                    revoked_certs[key_id] = revoked_cert
                    revoked = True

        if args.list_certs:
            for key_id, cert in items:
                print('Key ID          :', format_key_id(key_id))
                if not isinstance(cert, HackCertificate):
                    print('Serial Nr.      :', ":".join("%02x" % byte for byte in cert.serial_number.to_bytes(20, byteorder="big")))
                print('Issuer          :', cert.issuer.rfc4514_string())
                print('Subject         :', cert.subject.rfc4514_string())
                print('Valid Date Range:',
                    cert.not_valid_before.isoformat() if cert.not_valid_before is not None else 'N/A', '-',
                    cert.not_valid_after.isoformat()  if cert.not_valid_after  is not None else 'N/A')
                print('Version         :', cert.version.name)

                pk = cert.public_key()
                print(f'Key Type        : {type(pk).__name__.strip("_")}')
                if isinstance(pk, EllipticCurvePublicKey):
                    print( 'Curve           :', pk.curve.name)

                if not isinstance(cert, HackCertificate):
                    signature_algorithm_oid = cert.signature_algorithm_oid
                    print(f'Signature Algo. : oid={signature_algorithm_oid.dotted_string}, name={signature_algorithm_oid._name}')
                    print( 'Signature       :', b64encode(cert.signature).decode('ASCII'))

                if args.strip_revoked:
                    revoked_cert = revoked_certs.get(key_id)
                    if revoked_cert:
                        print('Revoked At      :', revoked_cert.revocation_date.isoformat())

                if args.print_exts and cert.extensions:
                    print('Extensions      :')
                    for ext in cert.extensions:
                        print(f'- oid={ext.oid.dotted_string}, name={ext.oid._name}, value={ext.value}')

                print()

        if args.strip_revoked:
            for key_id in revoked_certs:
                del certs[key_id]

        if args.save_certs:
            for certs_path in args.save_certs:
                save_certs(certs, certs_path, args.allow_public_key_only)

    ehc_codes: List[str] = []
    if args.image:
        from pyzbar.pyzbar import decode as decode_qrcode # type: ignore
        from PIL import Image # type: ignore

        for filename in args.ehc_code:
            image = Image.open(filename, 'r')
            qrcodes = decode_qrcode(image)
            if qrcodes:
                for qrcode in qrcodes:
                    ehc_codes.append(qrcode.data.decode("utf-8"))
            else:
                print_err(f'{filename}: no qr-code found')
    else:
        ehc_codes.extend(args.ehc_code)

    if args.no_verify:
        certs = None

    for ehc_code in ehc_codes:
        ehc_msg = decode_ehc(ehc_code)
        ehc_payload = cbor2.loads(ehc_msg.payload)

        for key, value in ehc_payload.items():
            if key != -260:
                name = CLAIM_NAMES.get(key)
                if name is not None:
                    if key in DATETIME_CLAIMS:
                        dt = EPOCH + timedelta(seconds=value)
                        value = dt.isoformat()
                else:
                    name = f'Claim {key} (unknown)'
                print(f'{name:15}: {value}')

        issued_at = EPOCH + timedelta(seconds=ehc_payload[6])

        expires_at_int = ehc_payload.get(4)
        if expires_at_int is not None:
            expires_at = EPOCH + timedelta(seconds=expires_at_int)
            print(f'Is Expired     :', datetime.utcnow() > expires_at)

        if certs is not None:
            verify_ehc(ehc_msg, issued_at, certs, args.print_exts)

        ehc = ehc_payload[-260][1]

        print('Payload        :')
        print(json.dumps(ehc, indent=4, sort_keys=True, default=json_serial))
        print()

if __name__ == '__main__':
    main()
