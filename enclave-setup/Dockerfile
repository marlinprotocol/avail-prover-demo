# base image
FROM alpine:3.17

# install dependency tools
RUN apk add --no-cache net-tools iptables iproute2 wget

# COPY transfer_params.bin ./params/transfer_params_prod.bin

# working directory
WORKDIR /app

# supervisord to manage programs
RUN wget -O supervisord http://public.artifacts.marlin.pro/projects/enclaves/supervisord_master_linux_amd64
RUN chmod +x supervisord

# transparent proxy component inside the enclave to enable outgoing connections
RUN wget -O ip-to-vsock-transparent http://public.artifacts.marlin.pro/projects/enclaves/ip-to-vsock-transparent_v1.0.0_linux_amd64
RUN chmod +x ip-to-vsock-transparent

# key generator to generate static keys
RUN wget -O keygen http://public.artifacts.marlin.pro/projects/enclaves/keygen_v1.0.0_linux_amd64
RUN chmod +x keygen

# attestation server inside the enclave that generates attestations
RUN wget -O attestation-server http://public.artifacts.marlin.pro/projects/enclaves/attestation-server_v2.0.0_linux_amd64
RUN chmod +x attestation-server

# proxy to expose attestation server outside the enclave
RUN wget -O vsock-to-ip http://public.artifacts.marlin.pro/projects/enclaves/vsock-to-ip_v1.0.0_linux_amd64
RUN chmod +x vsock-to-ip

# dnsproxy to provide DNS services inside the enclave
RUN wget -O dnsproxy http://public.artifacts.marlin.pro/projects/enclaves/dnsproxy_v0.46.5_linux_amd64
RUN chmod +x dnsproxy

RUN wget -O oyster-keygen http://public.artifacts.marlin.pro/projects/enclaves/keygen-secp256k1_v1.0.0_linux_amd64
RUN chmod +x oyster-keygen

# supervisord config
COPY supervisord.conf /etc/supervisord.conf

# setup.sh script that will act as entrypoint
COPY setup.sh ./
RUN chmod +x setup.sh

# generator-client api server
## used for generating/updating the config files and managing(start/stop/restart) the zk-proof generator
COPY generator-client ./
RUN chmod +x generator-client

COPY auth_test.txt ./

COPY fees.txt ./

COPY helper.txt ./

COPY multi_txn_t1.txt ./

COPY test_hello.txt ./

COPY id.sec ./

COPY id.pub ./

COPY secp.pub ./

COPY secp.sec ./

# generator-us
COPY kalypso-listener ./
RUN chmod +x kalypso-listener

# generator-used for generating zkproof
# COPY zkbob_generator ./
# RUN chmod +x zkbob_generator

# generator-used for generating avail proof
COPY avail-prover-demo ./
RUN chmod +x avail-prover-demo

# entry point
ENTRYPOINT [ "/app/setup.sh" ]
