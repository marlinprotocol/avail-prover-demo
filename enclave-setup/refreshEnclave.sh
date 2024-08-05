#!/bin/sh

# Check for the presence of the --debug argument
if [ "$1" = "--debug" ]; then
    DEBUG_MODE=true
else
    DEBUG_MODE=false
fi

# Always terminate all enclaves before starting a new one
nitro-cli terminate-enclave --all

# Conditionally run the enclave in debug mode if --debug was provided
if [ "$DEBUG_MODE" = true ]; then
    nitro-cli run-enclave --cpu-count 6 --memory 12000 --eif-path nitro-enclave.eif --enclave-cid 88 --debug-mode
else
    nitro-cli run-enclave --cpu-count 6 --memory 12000 --eif-path nitro-enclave.eif --enclave-cid 88
fi

# Connect to the console of the first enclave
nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
