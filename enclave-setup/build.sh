#!/bin/sh
nitro-cli terminate-enclave --all
FILE=nitro-enclave.eif
if [ -f "$FILE" ]; then
    rm $FILE
fi
docker rmi -f $(docker images -a -q)
docker build --no-cache ./ -t nitroimg
nitro-cli build-enclave --docker-uri nitroimg:latest --output-file nitro-enclave.eif
nitro-cli run-enclave --cpu-count 6 --memory 12000 --eif-path nitro-enclave.eif --enclave-cid 88
nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
