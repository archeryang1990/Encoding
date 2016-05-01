# ECDSA-256-SHA256-secp256r1
Encode/Decode data with ECDSA-256/SHA256, secp256r1

1. Generate ECDSA secp256r1 key pair:
------------------------------------------------------------------------------------------------
Install OpenSSL. When the executable in your path, enter this command to generate a private key:

openssl ecparam -genkey -name secp256k1 -noout -out myprivatekey.pem
To create the corresponding public key, do this:

openssl ec -in myprivatekey.pem -pubout -out mypubkey.pem
This will give you both keys in PEM format. I'm not sure what format the web page wants, but it shouldn't be difficult to convert. 
You can use variants of the last command to output other formats. 
Remove -pubout if you want the private key, leave it if you want the public key. 
And you can use -outform DER to get DER format. You can use -text to get hexadecimal.
------------------------------------------------------------------------------------------------

2. Encode
------------------------------------------------------------------------------------------------
Build command: gcc -o server -lssl -lcrypto -std=c99 server.c
Exe command: ./server test_token.bin
------------------------------------------------------------------------------------------------

3. Decode
------------------------------------------------------------------------------------------------
Build command: gcc -o client -lssl -lcrypto -std=c99 client.c
Exe command: ./client appeded_sig_token.bin
------------------------------------------------------------------------------------------------
