#!/usr/bin/env python3

from typing import Tuple, Any, Dict, Optional, List, FrozenSet

import json
import sys
import zlib
import re
import argparse
import codecs

from datetime import date, datetime, timedelta
from base64 import b64decode

import cbor2 # type: ignore
import cose.algorithms # type: ignore
import cose.keys.curves # type: ignore
import cose.keys.keytype # type: ignore
import requests

from base45 import b45decode # type: ignore
from cose.headers import KID # type: ignore
from cose.keys import CoseKey
from cose.keys.curves import CoseCurve, P256, P384, P521
from cose.keys.keyops import VerifyOp # type: ignore
from cose.keys.keyparam import KpAlg, EC2KpX, EC2KpY, EC2KpCurve, KpKty, RSAKpN, RSAKpE, KpKeyOps # type: ignore
from cose.keys.keytype import KtyEC2, KtyRSA
from cose.messages import CoseMessage # type: ignore
from cose.algorithms import Ps256, Es256
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
#from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from pyzbar.pyzbar import decode as decode_qrcode # type: ignore
from PIL import Image # type: ignore

# based on: https://github.com/ehn-digital-green-development/ehn-sign-verify-python-trivial

# Digital Green Certificate Gateway API SPEC: https://eu-digital-green-certificates.github.io/dgc-gateway/#/Trust%20Lists/downloadTrustList
# But where is it hosted?

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
CERTS_URL_DE = 'https://de.dscg.ubirch.com/trustList/DSC/'

# Netherlands public keys:
# https://www.npkd.nl/csca-health.html

# Keys from a French validation app, don't know if that is something official or a hobby project by someone:
# https://github.com/lovasoa/sanipasse/blob/master/src/assets/Digital_Green_Certificate_Signing_Keys.json

# Sweden:
# https://dgcg.covidbevis.se/tp/trust-list

# See also this thread:
# https://github.com/eu-digital-green-certificates/dgc-participating-countries/issues/10

DEBUG_KEY_IDS: FrozenSet[bytes] = frozenset(
    codecs.decode(key_id, 'hex')
    for key_id in {
        # EHCs generated with https://dgc.a-sit.at/ehn/ are signed with this key:
        b'd919375fc1e7b6b2',
    }
)

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
        cert = x509.load_der_x509_certificate(cert_data)
        fingerprint = cert.fingerprint(hashes.SHA256())
        if key_id != fingerprint[0:8]:
            raise ValueError(f'Key ID missmatch: {key_id.hex()} != {fingerprint[0:8].hex()}')

        certs[key_id] = cert

    return certs

def load_ehc_certs_signed_json(data: bytes) -> CertList:
    certs: CertList = {}

    sign_b64, body_json = data.split(b'\n', 1)
    sign = b64decode(sign_b64)
    body = json.loads(body_json)

    # TODO: Verify signature. Where to get the public key from?

    for cert in body['certificates']:
        key_id    = b64decode(cert['kid'])
        country   = cert['country']
        cert_type = cert['certificateType']
        if cert_type != 'DSC':
            print(f'[signed JSON cert list] unknown certificateType {cert_type!r} (country={country}, kid={key_id.hex()}', file=sys.stderr)
            continue

        raw_data = b64decode(cert['rawData'])

        cert = x509.load_der_x509_certificate(raw_data)
        fingerprint = cert.fingerprint(hashes.SHA256())
        if key_id != fingerprint[0:8]:
            raise ValueError(f'Key ID missmatch: {key_id.hex()} != {fingerprint[0:8].hex()}')

        certs[key_id] = cert

    return certs

def download_ehc_certs(sources: List[str], debug_certs: bool = False) -> CertList:
    certs = {}

    for source in sources:
        if source == 'AT':
            response = requests.get(CERTS_URL_AT)
            response.raise_for_status()
            certs_cbor = b64decode(json.loads(response.content)['trustList']['trustListContent'])
            certs_at = load_ehc_certs_cbor(certs_cbor)
            certs.update(certs_at)
        elif source == 'DE':
            response = requests.get(CERTS_URL_DE)
            response.raise_for_status()
            certs_signed_json = response.content
            certs_de = load_ehc_certs_signed_json(certs_signed_json)
            certs.update(certs_de)
        else:
            raise ValueError(f'Unknown trust list source: {source}')

    if not debug_certs:
        for key_id in DEBUG_KEY_IDS:
            if key_id in certs:
                del certs[key_id]

    return certs

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

def verify_ehc(msg: CoseMessage, certs: CertList) -> bool:
    given_kid = msg.phdr.get(KID) or msg.uhdr[KID]

    cert = certs.get(given_kid) # XXX: is this correct? is it not two levels of signed certificates?
    if not cert:
        raise KeyError(f'Key ID not found in cert list: {given_kid.hex()}')

    pk = cert.public_key()

    if isinstance(pk, EllipticCurvePublicKey):
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

    return msg.verify_signature()

def main() -> None:
    ap = argparse.ArgumentParser()
    certs_ap = ap.add_mutually_exclusive_group()
    certs_ap.add_argument('--certs-file', metavar="FILE", help='Trust list in CBOR format. If not given it will be downloaded from the internet.')
    certs_ap.add_argument('--certs-from', metavar="LIST", help="Download trust list from given country's trust list service. Entries from later country overwrites earlier. Supported countries: DE, AT (comma separated list, default: DE,AT)", default='DE,AT')

    verify_ap = ap.add_mutually_exclusive_group()
    verify_ap.add_argument('--no-verify', action='store_true', default=False, help='Skip certificate verification.')
    verify_ap.add_argument('--debug-certs', action='store_true', default=False, help='Keep debug trust list entries when verifying.')

    ap.add_argument('--image', action='store_true', default=False, help='Input is an image containing a QR-code.')
    ap.add_argument('ehc_code', nargs='*')

    args = ap.parse_args()

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

    for ehc_code in ehc_codes:
        ehc_msg = decode_ehc(ehc_code)
        ehc_payload = cbor2.loads(ehc_msg.payload)

        for key, value in ehc_payload.items():
            if key != -260:
                if key in CLAIM_NAMES:
                    name = CLAIM_NAMES[key]
                    if key in DATETIME_CLAIMS:
                        dt = datetime(1970, 1, 1) + timedelta(seconds=value)
                        value = dt.isoformat()
                else:
                    name = f'Claim {key} (unknown)'
                print(f'{name:15}: {value}')

        expires_at_int = ehc_payload.get(4)
        if expires_at_int is not None:
            expires_at = datetime(1970, 1, 1) + timedelta(seconds=expires_at_int)
            print(f'Is Expired     :', datetime.now() >= expires_at)

        if not args.no_verify:
            if args.certs_file:
                certs = load_ehc_certs(args.certs_file)
            else:
                certs = download_ehc_certs([country.strip().upper() for country in args.certs_from.split(',')], args.debug_certs)

            valid = verify_ehc(ehc_msg, certs)

            print(f'Signature Valid: {valid}')

        ehc = ehc_payload[-260][1]
        
        print('Payload        :')
        print(json.dumps(ehc, indent=4, sort_keys=True, default=json_serial))
        print()

if __name__ == '__main__':
    main()
