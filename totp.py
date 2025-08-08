# test_totp.py
import pyotp

secret = 'PASTE_SECRET_HERE_FROM_DB'

totp = pyotp.TOTP(secret)
print("Current code:", totp.now())
