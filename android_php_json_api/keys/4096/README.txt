
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -out public.pem -pubout
openssl rsa -in private.pem -out private_enc.pem -aes128 -passout pass:test


