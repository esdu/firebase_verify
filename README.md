# firebase_verify

Verify firebase tokens in python. (Ported from on the nodejs firebase lib)

## Requirements

- [python-jose](https://github.com/mpdavis/python-jose/)
- pycrypto
- ssl

## Usage

1. Open up `firebase_verify.py`

    a. Fix TODO about your PROJECT_ID

    b. Fix TODO about using your own caching layer

2. You're ready!

   ```
   from firebase_verify import verify_id_token
   print verify_id_token('eyJhbGciOiJSUzI1NiIsIm...')
   ```
