# Vendored OpenConfig gNMI Protos

Source repository: `https://github.com/openconfig/gnmi`

Pinned tag: `v0.10.0`

Pinned commit: `5473f2ef722ee45c3f26eee3f4a44a7d827e3575`

Vendored files:

- `github.com/openconfig/gnmi/proto/gnmi/gnmi.proto`
- `github.com/openconfig/gnmi/proto/gnmi_ext/gnmi_ext.proto`

Generation mode: build-time `tonic-build` using the system `protoc`. The build
script parses `option (gnmi_service)` from the vendored `gnmi.proto` and exposes
that value as the advertised gNMI version. Do not hard-code a different version
string in server code.
