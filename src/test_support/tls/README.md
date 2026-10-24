# Test TLS material

A test CA (`ca.pem`) and a leaf certificate with SANs `localhost` and `127.0.0.1`
(`leaf.pem`, `leaf.key`), valid for 100 years. A downstream loadcheck serves its fake upstream
over HTTPS with them and trusts the CA through `http::client_builder(Some(CA_PEM))`. The CA
key was discarded after signing. They protect nothing: never trust this CA anywhere else.

Regenerate (P-256 keys):

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout ca.key -out ca.pem -days 36500 -subj "/CN=mcp-starter test CA"
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout leaf.key -out leaf.csr -subj "/CN=localhost"
    printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n" > ext.cnf
    openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
      -out leaf.pem -days 36500 -extfile ext.cnf
    rm ca.key leaf.csr ext.cnf ca.srl
