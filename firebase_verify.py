from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from jose import jwt
import json
import re
import ssl
import time
import urllib2

PROJECT_ID = 'my-project-id' # TODO put your project id here
ALGORITHM = 'RS256'
CLIENT_CERT_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com'

class GoogleKeys(object):
    # TODO substitute this with your cache.
    PUBLIC_KEYS_CACHE = None
    PUBLIC_KEYS_EXPR = None
    @classmethod
    def fetch_public_keys(cls):
        if not cls.PUBLIC_KEYS_CACHE or not cls.PUBLIC_KEYS_EXPR or cls.PUBLIC_KEYS_EXPR < time.time():
            try:
                resp = urllib2.urlopen(CLIENT_CERT_URL)
                headers = resp.headers.dict
                cls.PUBLIC_KEYS_CACHE = json.loads(resp.read())
                if headers.get('cache-control'):
                    cache_exp_seconds = int(re.match('.*max-age=(.*?),.+', headers['cache-control']).groups()[0])
                    cls.PUBLIC_KEYS_EXPR = time.time() + cache_exp_seconds
            except Exception as e:
                raise Exception('Error fetching public keys for Google certs: {}'.format(e.message))

        return cls.PUBLIC_KEYS_CACHE

# http://stackoverflow.com/questions/12911373/how-do-i-use-a-x509-certificate-with-pycrypto
def cert_to_public_rsa_key(pem):
    DER = ssl.PEM_cert_to_DER_cert(pem)
    cert = DerSequence()
    cert.decode(DER)
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])
    subjectPublicKeyInfo = tbsCertificate[6]
    rsa_key = RSA.importKey(subjectPublicKeyInfo)
    return rsa_key

def verify_id_token(id_token):
    keys = GoogleKeys.fetch_public_keys()

    headers = jwt.get_unverified_header(id_token)
    #print '--- headers ---'
    #print headers
    #print '--- claims ---'
    claims = json.loads(jwt.get_unverified_claims(id_token))
    #print claims

    error_message = None
    if not headers.get('kid'):
        error_message = 'Firebase Auth ID token has no "kid" claim'
    elif headers.get('alg') != ALGORITHM:
        error_message = 'Firebase Auth ID token has incorrect algorithm'
    elif claims.get('aud') != PROJECT_ID:
        error_message = 'Firebase Auth ID token has incorrect "aud" claim'
    elif claims.get('iss') != 'https://securetoken.google.com/' + PROJECT_ID:
        error_message = 'Firebase Auth ID token has incorrect "iss" claim'
    elif not claims.get('sub') or len(claims['sub']) > 128:
        error_message = 'Firebase Auth ID token has invalid "sub" claim'

    if error_message:
        raise Exception(error_message)

    key = cert_to_public_rsa_key(keys[headers['kid']])

    result = jwt.decode(id_token, key, algorithms=[ALGORITHM], audience=PROJECT_ID)
    #print '--- verification ---'
    #print result

    return result

#
# debug & test
#

#import sys
#import logging
#logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
#
#import jose
#def test_verify_id_token(id_token):
#    try:
#        return verify_id_token(id_token)
#    except jose.exceptions.JWTError:
#        logging.error("Error: Invalid token")
#    except jose.exceptions.ExpiredSignatureError as e:
#        logging.error("{} {}".format(e.__class__, e))
#    except jose.exceptions.JWTClaimsError as e:
#        logging.error("{} {}".format(e.__class__, e))
#
# print test_verify_id_token('blahsomeinvalidtoken')
