#!/usr/bin/env bash
set -euo pipefail

if [[ "${OPC_NETCONF_INTEROP:-0}" != "1" ]]; then
    echo "SKIP: set OPC_NETCONF_INTEROP=1 to run ncclient interop smoke tests"
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: python3 not found on PATH"
    exit 0
fi

if ! python3 -c 'import ncclient' >/dev/null 2>&1; then
    echo "SKIP: Python package ncclient is not installed"
    exit 0
fi

missing=0
for name in OPC_NETCONF_HOST OPC_NETCONF_PORT OPC_NETCONF_USERNAME; do
    if [[ -z "${!name:-}" ]]; then
        echo "ERROR: ${name} is required when OPC_NETCONF_INTEROP=1" >&2
        missing=1
    fi
done
if [[ -z "${OPC_NETCONF_SSH_KEY:-}" && -z "${OPC_NETCONF_PASSWORD:-}" && "${OPC_NETCONF_ALLOW_AGENT:-0}" != "1" ]]; then
    echo "ERROR: set OPC_NETCONF_SSH_KEY, OPC_NETCONF_PASSWORD, or OPC_NETCONF_ALLOW_AGENT=1" >&2
    missing=1
fi
if [[ "${OPC_NETCONF_ENABLE_EDIT:-0}" == "1" && -z "${OPC_NETCONF_EDIT_CONFIG_FILE:-}" ]]; then
    echo "ERROR: OPC_NETCONF_EDIT_CONFIG_FILE is required when OPC_NETCONF_ENABLE_EDIT=1" >&2
    missing=1
fi
if [[ "${missing}" -ne 0 ]]; then
    exit 2
fi

echo "RUN: ncclient SSH smoke against ${OPC_NETCONF_HOST}:${OPC_NETCONF_PORT}"
python3 - <<'PY'
import os
from pathlib import Path
from ncclient import manager

def enabled(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default) == "1"

connect_args = {
    "host": os.environ["OPC_NETCONF_HOST"],
    "port": int(os.environ["OPC_NETCONF_PORT"]),
    "username": os.environ["OPC_NETCONF_USERNAME"],
    "timeout": int(os.environ.get("OPC_NETCONF_CONNECT_TIMEOUT", "10")),
    "hostkey_verify": enabled("OPC_NETCONF_HOSTKEY_VERIFY"),
    "allow_agent": enabled("OPC_NETCONF_ALLOW_AGENT"),
    "look_for_keys": enabled("OPC_NETCONF_LOOK_FOR_KEYS"),
    "device_params": {"name": "default"},
    "manager_params": {"timeout": int(os.environ.get("OPC_NETCONF_RPC_TIMEOUT", "10"))},
}

password = os.environ.get("OPC_NETCONF_PASSWORD")
if password:
    connect_args["password"] = password

key = os.environ.get("OPC_NETCONF_SSH_KEY")
if key:
    connect_args["key_filename"] = key

with manager.connect_ssh(**connect_args) as session:
    print(f"server-capabilities={len(session.server_capabilities)}")
    session.get_config(source="running")
    session.get()

    schema_id = os.environ.get("OPC_NETCONF_GET_SCHEMA_ID")
    if schema_id:
        session.get_schema(
            identifier=schema_id,
            version=os.environ.get("OPC_NETCONF_GET_SCHEMA_VERSION"),
            format=os.environ.get("OPC_NETCONF_GET_SCHEMA_FORMAT", "yang"),
        )

    if enabled("OPC_NETCONF_ENABLE_EDIT"):
        config = Path(os.environ["OPC_NETCONF_EDIT_CONFIG_FILE"]).read_text(encoding="utf-8")
        session.edit_config(
            target=os.environ.get("OPC_NETCONF_EDIT_TARGET", "running"),
            config=config,
            default_operation=os.environ.get("OPC_NETCONF_EDIT_DEFAULT_OPERATION", "merge"),
        )
        if os.environ.get("OPC_NETCONF_EDIT_TARGET", "running") == "candidate" and enabled("OPC_NETCONF_COMMIT_AFTER_EDIT"):
            session.commit()
PY
echo "PASS: ncclient interop smoke tests completed"
