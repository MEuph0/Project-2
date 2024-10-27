# CSCE 3550  Project 2: Extending the Basic JWKS Server
Mason Willy

## Server
A server with 2 endpoints: a RESTful JWKS endpoint tht serves public keys in JWKS format and a /auth endpoint that returns an unexpired, signed JWT on a POST request.

## Database File
A SQLite based file that is populated with private keys, one expired and one valid, upon the running the program. 

## Running the Program
The server can be ran with the follwoing command "py main.py" with Python3 and all requirements as outlined in the requirements.txt installed.

### Known Issues
Was having difficulty implementing the expiration time as a query parameter so opted for 0 and 1 being valid and expired for means of testing. May add functionality at a later date.

## Testing Programs
To assist in the testing of the server, the desktop application Postman was utilized for ease of making POST and GET requests without using a web browser. Additionally, jwt.io was utilizd to check the validity of signed JWTs.