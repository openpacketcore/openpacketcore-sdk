# OpenPacketCore SDK — top-level Makefile

.PHONY: generate-api generate-ngap

generate-api:
	python3 scripts/generate-api-nnrf.py --output crates/opc-api-nnrf/src/types.rs

generate-ngap:
	python3 scripts/generate-ngap.py --output crates/opc-proto-ngap/src/generated.rs
