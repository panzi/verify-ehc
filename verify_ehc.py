#!/usr/bin/env python3

from typing import Tuple, Any, Dict, Optional, List, FrozenSet, Union, Type

import json
import sys
import zlib
import re
import os
import argparse
import codecs

from os.path import splitext
from datetime import date, datetime, timedelta, timezone
from base64 import b64decode, b64encode, urlsafe_b64decode, urlsafe_b64encode

import cbor2 # type: ignore
import cose.algorithms # type: ignore
import cose.keys.curves # type: ignore
import cose.keys.keytype # type: ignore
import requests
import http.client

from dateutil.parser import isoparse as parse_datetime
from jose import jwt # type: ignore
from base45 import b45decode # type: ignore
from cose.headers import KID, Algorithm # type: ignore
from cose.keys import CoseKey
from cose.keys.curves import CoseCurve, P256, P384, P521
from cose.keys.keyops import VerifyOp # type: ignore
from cose.keys.keyparam import KpAlg, EC2KpX, EC2KpY, EC2KpCurve, KpKty, RSAKpN, RSAKpE, KpKeyOps # type: ignore
from cose.keys.keytype import KtyEC2, KtyRSA
from cose.messages import CoseMessage, Sign1Message # type: ignore
from cose.algorithms import Ps256, Es256
from cryptography import x509
from cryptography.x509 import load_der_x509_certificate, load_der_x509_crl, load_pem_x509_crl, Name, RelativeDistinguishedName, NameAttribute, Version, Extensions
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.name import _NAMEOID_TO_NAME
from cryptography.x509.oid import NameOID, ObjectIdentifier, SignatureAlgorithmOID, ExtensionOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key, load_der_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePublicNumbers, ECDSA, SECP256R1, EllipticCurve
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
#from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from pyzbar.pyzbar import decode as decode_qrcode # type: ignore
from PIL import Image # type: ignore

# based on: https://github.com/ehn-digital-green-development/ehn-sign-verify-python-trivial

# Digital Green Certificate Gateway API SPEC: https://eu-digital-green-certificates.github.io/dgc-gateway/#/Trust%20Lists/downloadTrustList
# But where is it hosted?

EPOCH = datetime(1970, 1, 1)

CertList = Dict[bytes, x509.Certificate]

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

NAME_OIDS = {name: name_oid for name_oid, name in _NAMEOID_TO_NAME.items()}

for name in dir(cose.keys.curves):
    if not name.startswith('_'):
        curve = getattr(cose.keys.curves, name)
        if curve is not CoseCurve and isinstance(curve, type) and issubclass(curve, CoseCurve) and curve.fullname != 'RESERVED': # type: ignore
            name = CURVE_NAME_IGNORE.sub('', curve.fullname).lower() # type: ignore
            COSE_CURVES[name] = curve
del name, curve

PREFIX = 'HC1:'

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

# Trust List used by German Digitaler-Impfnachweis app:
CERTS_URL_DE  = 'https://de.dscg.ubirch.com/trustList/DSC/'
PUBKEY_URL_DE = 'https://github.com/Digitaler-Impfnachweis/covpass-ios/raw/main/Certificates/PROD_RKI/CA/pubkey.pem'

# Netherlands public keys:
# (https://www.npkd.nl/csca-health.html)
# https://verifier-api.<acc/test/etc>.coronacheck.nl/v4/verifier/public_keys
CERTS_URL_NL = 'https://verifier-api.acc.coronacheck.nl/v4/verifier/public_keys'
# JSON containing base64 containing JSON containing base64 containing XML!

# Keys from a French validation app (nothing official, just a hobby project by someone):
# https://github.com/lovasoa/sanipasse/blob/master/src/assets/Digital_Green_Certificate_Signing_Keys.json

# French trust list:
# This requires the environment variable TACV_TOKEN to be set to a bearer token that can be found in the TousAntiCovid Verif app.
CERTS_URL_FR = 'https://portail.tacv.myservices-ingroupe.com/api/client/configuration/synchronisation/tacv'

# Sweden (JOSE encoded):
CERTS_URL_SW = 'https://dgcg.covidbevis.se/tp/trust-list'

# United Kingdom trust list:
CERTS_URL_UK = 'https://covid-pass-verifier.com/assets/certificates.json'

USER_AGENT = 'Mozilla/5.0 (Windows) Firefox/90.0'

# See also this thread:
# https://github.com/eu-digital-green-certificates/dgc-participating-countries/issues/10


class HackCertificate(x509.Certificate):
    _public_key: Union[EllipticCurvePublicKey, RSAPublicKey]
    _signature_algorithm_oid: ObjectIdentifier
    _issuer: Name
    _subject: Name
    _extensions: Extensions
    _not_valid_before: datetime
    _not_valid_after: datetime

    def __init__(self,
        public_key: Union[EllipticCurvePublicKey, RSAPublicKey],
        signature_algorithm_oid: ObjectIdentifier,
        issuer:  Name,
        subject: Name,
        not_valid_before: datetime = datetime(1970, 1, 1, tzinfo=timezone.utc),
        not_valid_after:  datetime = datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc),
    ):
        self._public_key = public_key
        self._signature_algorithm_oid = signature_algorithm_oid
        self._issuer  = issuer
        self._subject = subject
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

    def __as_tuple(self) -> Tuple[Union[EllipticCurvePublicKey, RSAPublicKey], ObjectIdentifier, Name, Name, Extensions]:
        return (self._public_key, self._signature_algorithm_oid, self._issuer, self._subject, self._extensions)

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
        return self._signature_algorithm_oid

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
    return load_ehc_certs_cbor(certs_cbor)

def load_ehc_certs_cbor(cbor_data: bytes) -> CertList:
    certs_data = cbor2.loads(cbor_data)
    certs: CertList = {}
    for item in certs_data['c']:
        key_id = item['i']
        cert_data = item['c']
        cert = load_der_x509_certificate(cert_data)
        fingerprint = cert.fingerprint(hashes.SHA256())
        if key_id != fingerprint[0:8]:
            raise ValueError(f'Key ID missmatch: {key_id.hex()} != {fingerprint[0:8].hex()}')

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

def load_hack_certs_json(data: bytes) -> CertList:
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
            cert = HackCertificate(ec_pubkey, SignatureAlgorithmOID.ECDSA_WITH_SHA256, issuer, subject)
            certs[key_id] = cert

        elif key_type == 'RSA':
            e_bytes = urlsafe_b64decode_ignore_padding(pubkey_dict['e'])
            n_bytes = urlsafe_b64decode_ignore_padding(pubkey_dict['n'])
            e = int.from_bytes(e_bytes, byteorder="big", signed=False)
            n = int.from_bytes(n_bytes, byteorder="big", signed=False)

            rsa_pubkey = RSAPublicNumbers(e, n).public_key()
            cert = HackCertificate(rsa_pubkey, SignatureAlgorithmOID.RSASSA_PSS, issuer, subject)
            certs[key_id] = cert

        else:
            raise TypeError(f'illegal key type: {key_type!r}')

    return certs

def print_err(msg: str) -> None:
    # so that errors and normal output is correctly interleaved:
    sys.stdout.flush()
    print(msg, file=sys.stderr)

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
            raise ValueError(f'Invalid signature DE trust list: {sign.hex()}')

    for cert in body['certificates']:
        key_id_b64 = cert['kid']
        key_id     = b64decode(key_id_b64)
        country    = cert['country']
        cert_type  = cert['certificateType']
        if cert_type != 'DSC':
            print_err(f'[signed JSON cert list] unknown certificateType {cert_type!r} (country={country}, kid={key_id.hex()}')
            continue

        raw_data = b64decode(cert['rawData'])

        try:
            cert = load_der_x509_certificate(raw_data)
        except Exception as error:
            print_err(f'ERROR: decoding DE trust list entry {key_id.hex()} / {key_id_b64}: {error}')
        else:
            fingerprint = cert.fingerprint(hashes.SHA256())
            if key_id != fingerprint[0:8]:
                raise ValueError(f'Key ID missmatch: {key_id.hex()} != {fingerprint[0:8].hex()}')

            certs[key_id] = cert

    return certs

def download_ehc_certs(sources: List[str]) -> CertList:
    certs = {}

    for source in sources:
        if source == 'AT':
            # TODO: find out how to verify signature?
            response = requests.get(CERTS_URL_AT, headers={'User-Agent': USER_AGENT})
            response.raise_for_status()
            certs_cbor = b64decode(json.loads(response.content)['trustList']['trustListContent'])
            certs_at = load_ehc_certs_cbor(certs_cbor)
            certs.update(certs_at)

        elif source == 'DE':
            response = requests.get(CERTS_URL_DE, headers={'User-Agent': USER_AGENT})
            response.raise_for_status()
            certs_signed_json = response.content

            pubkey: Optional[EllipticCurvePublicKey] = None
            response = requests.get(PUBKEY_URL_DE, headers={'User-Agent': USER_AGENT})
            if response.status_code == 404:
                print_err(f'{PUBKEY_URL_DE} pubkey for German trust list not found (404)!')
            else:
                response.raise_for_status()
                res_pubkey = load_pem_public_key(response.content)

                if not isinstance(res_pubkey, EllipticCurvePublicKey):
                    print_err(f'{PUBKEY_URL_DE} is expected to be an EllipticCurvePublicKey but actually is {type(res_pubkey).__name__}')
                else:
                    pubkey = res_pubkey

            certs_de = load_de_trust_list(certs_signed_json, pubkey)
            certs.update(certs_de)

        elif source == 'SW':
            # TODO: find out how to verify signature?
            response = requests.get(CERTS_URL_SW, headers={'User-Agent': USER_AGENT})
            response.raise_for_status()
            token_str = response.content.decode(response.encoding)
            token = jwt.get_unverified_claims(token_str)

            for country, country_keys in token['dsc_trust_list'].items():
                for entry in country_keys['keys']:
                    key_id = b64decode(entry['kid'])
                    for key_data in entry['x5c']:
                        try:
                            cert = load_der_x509_certificate(b64decode_ignore_padding(key_data))
                        except Exception as error:
                            print_err(f'ERROR: decoding SW trust list entry {key_id.hex()} / {b64encode(key_id).decode("ASCII")}: {error}')
                        else:
                            fingerprint = cert.fingerprint(hashes.SHA256())
                            if key_id != fingerprint[0:8]:
                                raise ValueError(f'Key ID missmatch: {key_id.hex()} != {fingerprint[0:8].hex()}')

                            certs[key_id] = cert

        elif source == 'UK' or source == 'GB':
            response = requests.get(CERTS_URL_UK, headers={'User-Agent': USER_AGENT})
            response.raise_for_status()
            certs_json = json.loads(response.content)
            for entry in certs_json:
                key_id   = bytes(entry['kid'])
                cert_der = bytes(entry['crt'])
                if cert_der:
                    try:
                        cert = load_der_x509_certificate(cert_der)
                    except Exception as error:
                        print_err(f'ERROR: decoding UK trust list entry {key_id.hex()} / {b64encode(key_id).decode("ASCII")}: {error}')
                    else:
                        fingerprint = cert.fingerprint(hashes.SHA256())
                        if key_id != fingerprint[0:8]:
                            raise ValueError(f'Key ID missmatch: {key_id.hex()} != {fingerprint[0:8].hex()}')

                        certs[key_id] = cert
                else:
                    iss = entry.get('iss')
                    if iss:
                        issuer = Name([NameAttribute(NAME_OIDS.get(key) or ObjectIdentifier(key), value) for key, value in iss.items()])
                    else:
                        issuer = Name([])

                    sub = entry.get('sub')
                    if sub:
                        subject = Name([NameAttribute(NAME_OIDS.get(key) or ObjectIdentifier(key), value) for key, value in sub.items()])
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
                        cert = HackCertificate(ec_pubkey, SignatureAlgorithmOID.ECDSA_WITH_SHA256, issuer, subject)
                        certs[key_id] = cert

                    elif 'n' in pub and 'e' in pub:
                        # RSA
                        e_bytes = bytes(pub['e'])
                        n_bytes = bytes(pub['n'])
                        e = int.from_bytes(e_bytes, byteorder="big", signed=False)
                        n = int.from_bytes(n_bytes, byteorder="big", signed=False)
                        rsa_pubkey = RSAPublicNumbers(e, n).public_key()
                        cert = HackCertificate(rsa_pubkey, SignatureAlgorithmOID.RSASSA_PSS, issuer, subject)
                        certs[key_id] = cert

                    else:
                        print_err(f'ERROR: decoding UK trust list entry {key_id.hex()} / {b64encode(key_id).decode("ASCII")}: no supported public key data found')

        elif source == 'FR':
            TACV_TOKEN = os.getenv('TACV_TOKEN')
            if TACV_TOKEN is None:
                raise KeyError(
                    'Required environment variable TACV_TOKEN for FR trust list is not set. '
                    'You can get the value of the token from the TousAntiCovid Verif application.')

            response = requests.get(CERTS_URL_FR, headers={
                'User-Agent': USER_AGENT,
                'Authorization': f'Bearer {TACV_TOKEN}',
            })
            response.raise_for_status()
            certs_json = json.loads(response.content)
            for key_id_b64, cert_b64 in certs_json['certificatesDCC'].items():
                key_id = b64decode(key_id_b64)
                cert_pem = b64decode(cert_b64)

                # Yes, they encode it twice!
                cert_der = b64decode(cert_pem)

                try:
                    try:
                        cert = load_der_x509_certificate(cert_der)
                    except ValueError:
                        cert = load_hack_certificate_from_der_public_key(cert_der)
                        # HackCertificate.fingerprint() is not implemented
                        certs[key_id] = cert

                    else:
                        fingerprint = cert.fingerprint(hashes.SHA256())
                        if key_id != fingerprint[0:8]:
                            raise ValueError(f'Key ID missmatch: {key_id.hex()} != {fingerprint[0:8].hex()}')

                        certs[key_id] = cert

                except Exception as error:
                    print_err(f'ERROR: decoding FR trust list entry {key_id.hex()} / {key_id_b64}: {error}')

        elif source == 'NL':
            response = requests.get(CERTS_URL_NL, headers={'User-Agent': USER_AGENT})
            response.raise_for_status()
            certs_json = json.loads(response.content)

            # TODO: find out how to verify signature?
            payload   = b64decode(certs_json['payload'])
            signature = b64decode(certs_json['signature'])

            payload_dict = json.loads(payload)
            # TODO: Don't know what to do with payload_dict['nl_keys'][*]['public_key']
            #       Its some strange XML (encoded as base64)
            for key_id_b64, pubkeys in payload_dict['eu_keys'].items():
                key_id = b64decode(key_id_b64)

                for entry in pubkeys:
                    # XXX: Why is pubkeys an array? How can there be more than one key to a key ID?
                    pubkey_der = b64decode(entry['subjectPk'])
                    # entry['keyUsage'] is array of 't' or 'v' or 'r'
                    try:
                        cert = load_hack_certificate_from_der_public_key(pubkey_der)
                    except Exception as error:
                        print_err(f'ERROR: decoding NL trust list entry {key_id.hex()} / {key_id_b64}: {error}')
                    else:
                        certs[key_id] = cert

        else:
            raise ValueError(f'Unknown trust list source: {source}')

    return certs

def load_hack_certificate_from_der_public_key(data: bytes) -> HackCertificate:
    pubkey = load_der_public_key(data)

    if isinstance(pubkey, EllipticCurvePublicKey):
        return HackCertificate(pubkey, SignatureAlgorithmOID.ECDSA_WITH_SHA256, Name([]), Name([]))
    elif isinstance(pubkey, RSAPublicKey):
        return HackCertificate(pubkey, SignatureAlgorithmOID.RSASSA_PSS, Name([]), Name([]))
    else:
        pubkey_type = type(pubkey)
        raise TypeError(f'unhandeled public key type: {pubkey_type.__module__}.{pubkey_type.__name__}')

def b64decode_ignore_padding(b64str: str) -> bytes:
    return b64decode(b64str + "=" * ((4 - len(b64str) % 4) % 4))

def urlsafe_b64decode_ignore_padding(b64str: str) -> bytes:
    return urlsafe_b64decode(b64str + "=" * ((4 - len(b64str) % 4) % 4))

def decode_ehc(b45_data: str) -> CoseMessage:
    if b45_data.startswith('HC1'):
        b45_data = b45_data[3:]
        if b45_data.startswith(':'):
            b45_data = b45_data[1:]

    try:
        data = b45decode(b45_data)
    except ValueError:
        raise ValueError(f'Invalid base45 string. Try with single quotes.') from None

    if data.startswith(b'x'):
        data = zlib.decompress(data)

    msg: CoseMessage = CoseMessage.decode(data)
    return msg

def verify_ehc(msg: CoseMessage, issued_at: datetime, certs: CertList, print_exts: bool = False) -> bool:
    cose_algo = msg.phdr.get(Algorithm) or msg.uhdr.get(Algorithm)
    print(f'COSE Sig. Algo.: {cose_algo.fullname if cose_algo is not None else "N/A"}')
    if isinstance(msg, Sign1Message):
        print(f'Signature      : {b64encode(msg.signature).decode("ASCII")}')

    given_kid = msg.phdr.get(KID) or msg.uhdr[KID]
    print(f'Key ID         : {given_kid.hex()} / {b64encode(given_kid).decode("ASCII")}')

    cert = certs.get(given_kid) # XXX: is this correct? is it not two levels of signed certificates?
    if not cert:
        raise KeyError(f'Key ID not found in cert list: {given_kid.hex()}')

    pk = cert.public_key()
    print(f'Key Type       : {type(pk).__name__.strip("_")}')
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

    signature_algorithm_oid = cert.signature_algorithm_oid
    print(f'Signature Algo.: oid={signature_algorithm_oid.dotted_string}, name={signature_algorithm_oid._name}')
    print( 'Cert Signature :', b64encode(cert.signature).decode('ASCII'))

    if isinstance(pk, EllipticCurvePublicKey):
        print(f'Curve          : {pk.curve.name}')
        rsa_pn = pk.public_numbers()
        size = pk.curve.key_size // 8

        x = rsa_pn.x.to_bytes(size, byteorder="big")
        y = rsa_pn.y.to_bytes(size, byteorder="big")

        curve_name = CURVE_NAME_IGNORE.sub('', pk.curve.name).lower()
        curve = COSE_CURVES.get(curve_name)

        if not curve:
            raise KeyError(f'Unsupported curve: {pk.curve.name}')

        msg.key = CoseKey.from_dict(
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
        dsa_pn = pk.public_numbers()
        e = dsa_pn.e.to_bytes((dsa_pn.e.bit_length() + 7) // 8, byteorder='big')
        n = dsa_pn.n.to_bytes((dsa_pn.n.bit_length() + 7) // 8, byteorder='big')

        msg.key = CoseKey.from_dict(
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
    #    msg.key = CoseKey.from_dict(
    #        {
    #            # ???
    #        }
    #    )
    else:
        raise KeyError(f'Unsupported public key type: {type(pk).__name__}')

    valid = msg.verify_signature()

    print(f'Signature Valid: {valid}')

    if print_exts and cert.extensions:
        print('Extensions     :')
        for ext in cert.extensions:
            print(f'- oid={ext.oid.dotted_string}, name={ext.oid._name}, value={ext.value}')

    return valid and not cert_expired and not revoked

crl_status: Dict[str, int] = {}
crls: Dict[str, x509.CertificateRevocationList] = {}

def get_cached_crl(uri: str) -> x509.CertificateRevocationList:
    crl = crls.get(uri)

    if crl is not None:
        return crl

    status_code = crl_status.get(uri)
    if status_code is not None:
        raise ValueError(f'{status_code} {http.client.responses.get(status_code, "")}')

    response = requests.get(uri, headers={'User-Agent': USER_AGENT})
    status_code = response.status_code
    crl_status[uri] = status_code

    if response.status_code >= 400 and response.status_code < 600:
        msg = f'{status_code} {http.client.responses.get(status_code, "")}'
        print_err(f'ERROR: loading revokation list {uri} {msg}')
        raise ValueError(msg)

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
                            print_err(f'ERROR: loading revokation list {uri.value} {error}')
                        else:
                            return crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    return None

def main() -> None:
    ap = argparse.ArgumentParser()

    certs_ap = ap.add_mutually_exclusive_group()
    certs_ap.add_argument('--certs-file', metavar="FILE", help='Trust list in CBOR format. If not given it will be downloaded from the internet.')
    certs_ap.add_argument('--certs-from', metavar="LIST", help=
        "Download trust list from given country's trust list service. Entries from later country overwrites earlier. "
        "Supported countries: AT, DE, FR, NL, SW, UK (comma separated list). "
        "FR needs the environment varialbe TACV_TOKEN set to a bearer token that can be found in the TousAntiCovid Verif app. "
        "(default: DE,AT)",
        default='DE,AT')

    ap.add_argument('--no-verify', action='store_true', default=False, help='Skip certificate verification.')

    ap.add_argument('--list-certs', action='store_true', help='List certificates from trust list.')
    ap.add_argument('--print-exts', action='store_true', help='Also print certificate extensions.')
    ap.add_argument('--strip-revoked', action='store_true', help='Strip revoked certificates. (Downloads certificate revocation list, if supported by certificate.)')
    ap.add_argument('--save-certs', metavar='FILE', help='Store downloaded certificates to FILE. The filetype is derived from the extension, which can be .json or .cbor')

    ap.add_argument('--image', action='store_true', default=False, help='ehc_code is a path to an image file containing a QR-code.')
    ap.add_argument('ehc_code', nargs='*', help='Scanned EHC QR-code, or when --image is passed path to an image file.')

    args = ap.parse_args()

    certs: Optional[CertList] = None
    if not args.no_verify or args.save_certs or args.list_certs:
        if args.certs_file:
            if args.certs_file.lower().endswith('.json'):
                with open(args.certs_file, 'rb') as fp:
                    certs_data = fp.read()
                certs = load_hack_certs_json(certs_data)
            else:
                certs = load_ehc_certs(args.certs_file)
        else:
            certs = download_ehc_certs([country.strip().upper() for country in args.certs_from.split(',')])

        if args.save_certs:
            ext = splitext(args.save_certs)[1]
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

                with open(args.save_certs, 'w') as text_stream:
                    json.dump(json_doc, text_stream)

            elif lower_ext == '.cbor':
                # same CBOR format as AT trust list
                cert_list: List[dict] = []
                for key_id, cert in certs.items():
                    try:
                        cert_bytes = cert.public_bytes(Encoding.DER)
                    except NotImplementedError as error:
                        print_err(f'ERROR: Cannot store entry {key_id.hex()} / {b64encode(key_id).decode("ASCII")} in CBOR trust list: {error}')
                    else:
                        cert_list.append({
                            'i': key_id,
                            'c': cert_bytes,
                        })
                with open(args.save_certs, 'wb') as fp:
                    cbor2.dump({'c': cert_list}, fp)
            else:
                raise ValueError(f'Unsupported certificates file extension: {ext!r}')

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
                signature_algorithm_oid = cert.signature_algorithm_oid
                print('Key ID          :', key_id.hex(), '/', b64encode(key_id).decode("ASCII"))
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

    ehc_codes: List[str] = []
    if args.image:
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
            print(f'Is Expired     :', datetime.now() >= expires_at)

        if certs is not None:
            verify_ehc(ehc_msg, issued_at, certs, args.print_exts)

        ehc = ehc_payload[-260][1]
        
        print('Payload        :')
        print(json.dumps(ehc, indent=4, sort_keys=True, default=json_serial))
        print()

if __name__ == '__main__':
    main()
