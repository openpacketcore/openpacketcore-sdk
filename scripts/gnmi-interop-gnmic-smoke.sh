#!/usr/bin/env bash
set -euo pipefail

if [[ "${OPC_GNMI_INTEROP:-0}" != "1" ]]; then
    echo "SKIP: set OPC_GNMI_INTEROP=1 to run gnmic interop smoke tests"
    exit 0
fi

if ! command -v gnmic >/dev/null 2>&1; then
    echo "SKIP: gnmic not found on PATH"
    exit 0
fi

missing=0
for name in \
    OPC_GNMI_ADDR \
    OPC_GNMI_CA_CERT \
    OPC_GNMI_CLIENT_CERT \
    OPC_GNMI_CLIENT_KEY
do
    if [[ -z "${!name:-}" ]]; then
        echo "ERROR: ${name} is required when OPC_GNMI_INTEROP=1" >&2
        missing=1
    fi
done
if [[ "${missing}" -ne 0 ]]; then
    exit 2
fi

OPC_GNMI_TIMEOUT="${OPC_GNMI_TIMEOUT:-10s}"
OPC_GNMI_GET_PATH="${OPC_GNMI_GET_PATH:-/system/hostname}"
OPC_GNMI_SUBSCRIBE_PATH="${OPC_GNMI_SUBSCRIBE_PATH:-${OPC_GNMI_GET_PATH}}"

gnmic_base=(
    gnmic
    --address "${OPC_GNMI_ADDR}"
    --tls-ca "${OPC_GNMI_CA_CERT}"
    --tls-cert "${OPC_GNMI_CLIENT_CERT}"
    --tls-key "${OPC_GNMI_CLIENT_KEY}"
    --timeout "${OPC_GNMI_TIMEOUT}"
    --encoding json_ietf
)

if [[ -n "${OPC_GNMI_TLS_SERVER_NAME:-}" ]]; then
    gnmic_base+=(--tls-server-name "${OPC_GNMI_TLS_SERVER_NAME}")
fi

echo "RUN: gnmic capabilities"
"${gnmic_base[@]}" capabilities >/dev/null

echo "RUN: gnmic get ${OPC_GNMI_GET_PATH}"
"${gnmic_base[@]}" get --path "${OPC_GNMI_GET_PATH}" >/dev/null

echo "RUN: gnmic subscribe once ${OPC_GNMI_SUBSCRIBE_PATH}"
"${gnmic_base[@]}" subscribe --mode once --path "${OPC_GNMI_SUBSCRIBE_PATH}" >/dev/null

if [[ "${OPC_GNMI_ENABLE_SET:-0}" == "1" ]]; then
    if [[ -z "${OPC_GNMI_SET_PATH:-}" || -z "${OPC_GNMI_SET_JSON:-}" ]]; then
        echo "ERROR: OPC_GNMI_SET_PATH and OPC_GNMI_SET_JSON are required when OPC_GNMI_ENABLE_SET=1" >&2
        exit 2
    fi
    echo "RUN: gnmic set ${OPC_GNMI_SET_PATH}"
    "${gnmic_base[@]}" set \
        --update-path "${OPC_GNMI_SET_PATH}" \
        --update-value "${OPC_GNMI_SET_JSON}" >/dev/null
else
    echo "SKIP: set OPC_GNMI_ENABLE_SET=1 to include a mutating Set smoke test"
fi

echo "PASS: gnmic interop smoke tests completed"
