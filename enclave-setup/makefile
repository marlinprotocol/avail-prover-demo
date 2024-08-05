PROJECTS := kalypso-listener generator-client zkbob-generator oyster-attestation-utility
all: $(PROJECTS)

kalypso-listener:
	@echo "Building kalypso-listener... "
	@cd dependencies/kalypso-unified && cargo build --release -p listener
	@cp dependencies/kalypso-listener/target/x86_64-unknown-linux-musl/release/listener kalypso-listener

generator-client:
	@echo "Building generator-client... "
	@cd dependencies/kalypso-unified && cargo build --release -p generator_client
	@cp dependencies/generator-client/target/x86_64-unknown-linux-musl/release/generator-client generator-client

zkbob-generator:
	@echo "Building zkbob-generator... "
	@cd dependencies/zkbob-generator && cargo build --release
	@cp dependencies/zkbob-generator/target/release/zkbob-generator zkbob-generator 

avail-prover-demo:
	@echo "Building avail-prover-demo... "
	@cd dependencies/avail-prover-demo && cargo build --release
	@cp dependencies/Avail-prover-demo/target/release/avail-prover-demo avail-prover-demo

oyster-attestation-utility:
	@echo "Building oyster-attestation-utility... "
	@cd dependencies/oyster-attestation-server-secp256k1 && cargo build --release
	@cp dependencies/oyster-attestation-server-secp256k1/target/release/oyster-attestation-server-secp256k1 oyster-attestation-utility 

.PHONY: clone-repos
clone-repos:
	@echo "Cloning Repo"
	@mkdir -p dependencies 
	@cd dependencies && git clone https://github.com/marlinprotocol/kalypso-unified.git
	@cd dependencies && git clone https://github.com/marlinprotocol/zkbob-generator.git
	@cd dependencies && git clone https://github.com/marlinprotocol/oyster-attestation-server-secp256k1

.PHONY: pull-repo
pull-repo:   
	@echo "Pulling Repo"
	@cd dependencies/zkbob-generator && git pull
	@cd dependencies && git clone https://github.com/marlinprotocol/kalypso-unified.git
	@cd dependencies/oyster-attestation-server-secp256k1 && git pull

.PHONY: clean
clean:
	@rm -f zkbob-generator generator-client kalypso-listener oyster-attestation-utility avail-prover-demo
	@rm -rf dependencies
