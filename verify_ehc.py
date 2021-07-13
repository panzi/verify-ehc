#!/usr/bin/env python3

from typing import Tuple, Any, Dict, Optional, List, FrozenSet, Union

import json
import sys
import zlib
import re
import argparse
import codecs

from os.path import splitext
from datetime import date, datetime, timedelta
from base64 import b64decode, b64encode, urlsafe_b64decode, urlsafe_b64encode

import cbor2 # type: ignore
import cose.algorithms # type: ignore
import cose.keys.curves # type: ignore
import cose.keys.keytype # type: ignore
import requests

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
from cryptography.x509 import load_der_x509_certificate
from cryptography.x509.oid import NameOID, ObjectIdentifier, SignatureAlgorithmOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePublicNumbers, ECDSA
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

CURVES: Dict[str, type] = {
    # https://tools.ietf.org/search/rfc4492#appendix-A
    'secp256r1':  P256,
    'prime256v1': P256,
    'secp384r1':  P384,
    'secp521r1':  P521,
}

for name in dir(cose.keys.curves):
    if not name.startswith('_'):
        curve = getattr(cose.keys.curves, name)
        if curve is not CoseCurve and isinstance(curve, type) and issubclass(curve, CoseCurve) and curve.fullname != 'RESERVED': # type: ignore
            name = CURVE_NAME_IGNORE.sub('', curve.fullname).lower() # type: ignore
            CURVES[name] = curve
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
# https://www.npkd.nl/csca-health.html

# Keys from a French validation app (nothing official, just a hobby project by someone):
# https://github.com/lovasoa/sanipasse/blob/master/src/assets/Digital_Green_Certificate_Signing_Keys.json

# Sweden (JOSE encoded):
CERTS_URL_SW = 'https://dgcg.covidbevis.se/tp/trust-list'

# United Kingdom trust list:
CERTS_URL_UK = 'https://covid-pass-verifier.com/assets/certificates.json'

# See also this thread:
# https://github.com/eu-digital-green-certificates/dgc-participating-countries/issues/10

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

def load_ehc_certs_signed_json(data: bytes, pubkey: Optional[EllipticCurvePublicKey] = None) -> CertList:
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
        key_id    = b64decode(cert['kid'])
        country   = cert['country']
        cert_type = cert['certificateType']
        if cert_type != 'DSC':
            print(f'[signed JSON cert list] unknown certificateType {cert_type!r} (country={country}, kid={key_id.hex()}', file=sys.stderr)
            continue

        raw_data = b64decode(cert['rawData'])

        cert = load_der_x509_certificate(raw_data)
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
            response = requests.get(CERTS_URL_AT)
            response.raise_for_status()
            certs_cbor = b64decode(json.loads(response.content)['trustList']['trustListContent'])
            certs_at = load_ehc_certs_cbor(certs_cbor)
            certs.update(certs_at)

        elif source == 'DE':
            response = requests.get(CERTS_URL_DE)
            response.raise_for_status()
            certs_signed_json = response.content

            pubkey: Optional[EllipticCurvePublicKey] = None
            response = requests.get(PUBKEY_URL_DE)
            if response.status_code == 404:
                print(f'{PUBKEY_URL_DE} pubkey for German trust list not found (404)!', file=sys.stderr)
            else:
                response.raise_for_status()
                res_pubkey = load_pem_public_key(response.content)

                if not isinstance(res_pubkey, EllipticCurvePublicKey):
                    print(f'{PUBKEY_URL_DE} is expected to be an EllipticCurvePublicKey but actually is {type(res_pubkey).__name__}', file=sys.stderr)
                else:
                    pubkey = res_pubkey

            certs_de = load_ehc_certs_signed_json(certs_signed_json, pubkey)
            certs.update(certs_de)

        elif source == 'SW':
            # TODO: find out how to verify signature?
            response = requests.get(CERTS_URL_SW)
            response.raise_for_status()
            token_str = response.content.decode(response.encoding)
            token = jwt.get_unverified_claims(token_str)

            for country, country_keys in token['dsc_trust_list'].items():
                for entry in country_keys['keys']:
                    key_id = b64decode(entry['kid'])
                    for key_data in entry['x5c']:
                        cert = load_der_x509_certificate(b64decode_ignore_padding(key_data))

                        fingerprint = cert.fingerprint(hashes.SHA256())
                        if key_id != fingerprint[0:8]:
                            raise ValueError(f'Key ID missmatch: {key_id.hex()} != {fingerprint[0:8].hex()}')

                        certs[key_id] = cert

        elif source == 'UK':
            response = requests.get(CERTS_URL_UK)
            response.raise_for_status()
            certs_json = json.loads(response.content)
            for entry in certs_json:
                key_id   = bytes(entry['kid'])
                cert_der = bytes(entry['crt'])
                cert = load_der_x509_certificate(cert_der)

                fingerprint = cert.fingerprint(hashes.SHA256())
                if key_id != fingerprint[0:8]:
                    raise ValueError(f'Key ID missmatch: {key_id.hex()} != {fingerprint[0:8].hex()}')

                certs[key_id] = cert

        else:
            raise ValueError(f'Unknown trust list source: {source}')

    return certs

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

def verify_ehc(msg: CoseMessage, issued_at: datetime, certs: CertList) -> bool:
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
        curve = CURVES.get(curve_name)

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

    return valid and not cert_expired

def main() -> None:
    ap = argparse.ArgumentParser()

    certs_ap = ap.add_mutually_exclusive_group()
    certs_ap.add_argument('--certs-file', metavar="FILE", help='Trust list in CBOR format. If not given it will be downloaded from the internet.')
    certs_ap.add_argument('--certs-from', metavar="LIST", help="Download trust list from given country's trust list service. Entries from later country overwrites earlier. Supported countries: AT, DE, SW, UK (comma separated list, default: DE,AT)", default='DE,AT')

    ap.add_argument('--no-verify', action='store_true', default=False, help='Skip certificate verification.')

    ap.add_argument('--list-certs', action='store_true', help='List certificates from trust list.')
    ap.add_argument('--save-certs', metavar='FILE', help='Store downloaded certificates to FILE. The filetype is derived from the extension, which can be .json or .cbor')

    ap.add_argument('--image', action='store_true', default=False, help='Input is an image containing a QR-code.')
    ap.add_argument('ehc_code', nargs='*')

    args = ap.parse_args()

    certs: Optional[CertList] = None
    if not args.no_verify or args.save_certs or args.list_certs:
        if args.certs_file:
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
                        'issuer':  cert.issuer.rfc4514_string(),
                        'subject': cert.subject.rfc4514_string(),
                        'notValidBefore': cert.not_valid_before.isoformat(),
                        'notValidAfter':  cert.not_valid_after.isoformat(),
                        'publicKey': pubkey_json,
                        'algorithm': algo,
                    }

                    certs_json[key_id.hex()] = cert_json

                with open(args.save_certs, 'w') as text_stream:
                    json.dump({'trustList': certs_json}, text_stream)

            elif lower_ext == '.cbor':
                # same CBOR format as AT trust list
                with open(args.save_certs, 'wb') as fp:
                    cbor2.dump({'c': [
                        {'i': key_id, 'c': cert.public_bytes(Encoding.DER)}
                        for key_id, cert in certs.items()
                    ]}, fp)
            else:
                raise ValueError(f'Unsupported certificates file extension: {ext!r}')

        if args.list_certs:
            items = list(certs.items())
            items.sort(key=lambda item: (item[1].issuer.rfc4514_string(), item[1].subject.rfc4514_string(), item[0]))

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
                print()

    ehc_codes: List[str] = []
    if args.image:
        for filename in args.ehc_code:
            image = Image.open(filename, 'r')
            qrcodes = decode_qrcode(image)
            if qrcodes:
                for qrcode in qrcodes:
                    ehc_codes.append(qrcode.data.decode("utf-8"))
            else:
                print(f'{filename}: no qr-code found', file=sys.stderr)
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
            verify_ehc(ehc_msg, issued_at, certs)

        ehc = ehc_payload[-260][1]
        
        print('Payload        :')
        print(json.dumps(ehc, indent=4, sort_keys=True, default=json_serial))
        print()

if __name__ == '__main__':
    main()
