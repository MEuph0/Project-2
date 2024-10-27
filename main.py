''' 
CSCE 3550 Project 2
Mason Willy

'''

from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import sqlite3
import base64
import json
import jwt
import datetime

hostName = "localhost"
serverPort = 8080

''' Create a database file and populate with private keys'''
conn = sqlite3.connect("totally_not_my_privateKeys.db")
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)''')
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
cursor.execute("INSERT INTO keys (key, exp) VALUES (?,?)", (pem, False))
cursor.execute("INSERT INTO keys (key, exp) VALUES (?,?)", (expired_pem, True))
conn.commit()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    ''' Updated POST function to use database file '''
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":

            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                cursor.execute('SELECT * FROM keys WHERE exp=True')
                row = cursor.fetchone()
                pem = row[1]
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            else:
                cursor.execute('SELECT * FROM keys')
                row = cursor.fetchone()
                pem = row[1]

            headers = {
                "kid": f"{row[0]}"
            }
            
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    ''' Updated GET function to use database '''
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            time = datetime.datetime.now()
            cursor.execute('SELECT * FROM keys WHERE exp=False')
            rows = cursor.fetchall()
            keys = {"keys": []}
            for row in rows:
                key = serialization.load_pem_private_key(row[1], password=None)
                numbers = key.private_numbers()
                jwt_key = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": f"{row[0]}",
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                }
                keys["keys"].append(jwt_key)
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    
    conn.close()
    webServer.server_close()
