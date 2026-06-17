#!/usr/bin/env bash
set -euo pipefail

if [[ "${OPC_NETCONF_INTEROP:-0}" != "1" ]]; then
    echo "SKIP: set OPC_NETCONF_INTEROP=1 to run netopeer2-cli interop smoke tests"
    exit 0
fi

if ! command -v netopeer2-cli >/dev/null 2>&1; then
    echo "SKIP: netopeer2-cli not found on PATH"
    exit 0
fi

OPC_NETCONF_TRANSPORT="${OPC_NETCONF_TRANSPORT:-ssh}"
OPC_NETCONF_HOST="${OPC_NETCONF_HOST:-127.0.0.1}"
OPC_NETCONF_PORT="${OPC_NETCONF_PORT:-830}"

missing=0
case "${OPC_NETCONF_TRANSPORT}" in
    ssh)
        for name in OPC_NETCONF_USERNAME OPC_NETCONF_SSH_KEY; do
            if [[ -z "${!name:-}" ]]; then
                echo "ERROR: ${name} is required for netopeer2-cli SSH interop" >&2
                missing=1
            fi
        done
        ;;
    tls)
        for name in OPC_NETCONF_CLIENT_CERT OPC_NETCONF_CLIENT_KEY OPC_NETCONF_CA_CERT; do
            if [[ -z "${!name:-}" ]]; then
                echo "ERROR: ${name} is required for netopeer2-cli TLS interop" >&2
                missing=1
            fi
        done
        ;;
    *)
        echo "ERROR: OPC_NETCONF_TRANSPORT must be ssh or tls" >&2
        exit 2
        ;;
esac
if [[ "${missing}" -ne 0 ]]; then
    exit 2
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
cmd_file="${tmp_dir}/netopeer2-cli.commands"

{
    if [[ "${OPC_NETCONF_TRANSPORT}" == "ssh" ]]; then
        echo "knownhosts --mode accept-new"
        echo "auth pref password -1"
        echo "auth pref interactive -1"
        echo "auth pref publickey 3"
        echo "auth keys add ${OPC_NETCONF_SSH_KEY}"
        echo "connect --host ${OPC_NETCONF_HOST} --port ${OPC_NETCONF_PORT} --ssh --login ${OPC_NETCONF_USERNAME}"
    else
        echo "connect --host ${OPC_NETCONF_HOST} --port ${OPC_NETCONF_PORT} --tls --cert ${OPC_NETCONF_CLIENT_CERT} --key ${OPC_NETCONF_CLIENT_KEY} --trusted ${OPC_NETCONF_CA_CERT}"
    fi
    echo "get-config --source running"
    echo "get"
    if [[ "${OPC_NETCONF_ENABLE_EDIT:-0}" == "1" ]]; then
        if [[ -z "${OPC_NETCONF_EDIT_CONFIG_FILE:-}" ]]; then
            echo "disconnect"
            echo "exit"
            echo "ERROR: OPC_NETCONF_EDIT_CONFIG_FILE is required when OPC_NETCONF_ENABLE_EDIT=1" >&2
            exit 2
        fi
        echo "edit-config --target ${OPC_NETCONF_EDIT_TARGET:-running} --config ${OPC_NETCONF_EDIT_CONFIG_FILE}"
        if [[ "${OPC_NETCONF_EDIT_TARGET:-running}" == "candidate" && "${OPC_NETCONF_COMMIT_AFTER_EDIT:-0}" == "1" ]]; then
            echo "commit"
        fi
    fi
    echo "disconnect"
    echo "exit"
} >"${cmd_file}"

echo "RUN: netopeer2-cli ${OPC_NETCONF_TRANSPORT} smoke against ${OPC_NETCONF_HOST}:${OPC_NETCONF_PORT}"
HOME="${tmp_dir}" netopeer2-cli <"${cmd_file}" >/dev/null
echo "PASS: netopeer2-cli interop smoke tests completed"
