# OpenPacketCore SDK — top-level Makefile

.PHONY: generate-api

generate-api:
	python3 scripts/generate-api-nnrf.py --output crates/opc-api-nnrf/src/types.rs
