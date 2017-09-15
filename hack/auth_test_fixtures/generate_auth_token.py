'''
Script to generate an authentication token to be passed as header
with requests to Bayesian API
'''

import jwt
import datetime
import base64

expiry = datetime.datetime.utcnow() + datetime.timedelta(days=90)
userid = "testuser"
f1 = open('./private_key.pem', 'r')
bayesian_private_key = f1.read()
token = ""

try:
    payload = {
        'exp': expiry,
        'iat': datetime.datetime.utcnow(),
        'sub': userid
    }
    token = jwt.encode(payload, key=bayesian_private_key, algorithm='RS256')
    print(token.decode('utf-8'))
except Exception as e:
    print(e)

#  Following lines are for testing purpose only
# def decode():
#     f2 = open('./public_key.pem', 'r')
#     bayesian_public_key = f2.read()
#     try:
#         string = jwt.decode(token, key=bayesian_public_key, algorithm='RS256')
#     except Exception as e:
#         print (e)
#     print (string)
#
# decode()
