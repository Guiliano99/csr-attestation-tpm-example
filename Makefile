
csr ?= verifier/key1-csr.pem
print-csr:
	openssl req -in $(csr) -noout -text

print-ak-cert:
	openssl x509 -in verifier/ak-cert.pem -noout -text

run-simulator:
	./docker/run.sh
