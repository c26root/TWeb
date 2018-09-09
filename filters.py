import hashlib
import base64

def md5(s):
    return hashlib.md5(s).hexdigest()

def sha1(s):
    return hashlib.sha1(s).hexdigest()

def sha224(s):
    return hashlib.sha224(s).hexdigest()

def sha256(s):
    return hashlib.sha256(s).hexdigest()

def sha384(s):
    return hashlib.sha384(s).hexdigest()

def sha512(s):
    return hashlib.sha512(s).hexdigest()

def base64encode(s):
    try:
        return base64.b64encode(s)
    except Exception as e:
        return e

def base64decode(s):
    try:
        return base64.b64decode(s)
    except Exception as e:
        return str(e)
