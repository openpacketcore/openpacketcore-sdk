#!/usr/bin/env bash
# Qualify the production TFT fallback in a separately booted, disposable guest.
set -euo pipefail

if [[ $# -ne 4 || "$2" != /* || "$3" != /* || "$4" != /* ]]; then
  echo 'usage: qualify-tft-nohz-vm.sh {linux68|el9} ABSOLUTE_BINARY_DIRECTORY ABSOLUTE_PACKAGE_DIRECTORY ABSOLUTE_STATE_DIRECTORY' >&2
  exit 2
fi
profile="$1"
binaries="$2"
packages="$3"
state="$4"
case "$profile" in
  linux68)
    image_url='https://cloud-images.ubuntu.com/releases/noble/release-20260705/ubuntu-24.04-server-cloudimg-amd64.img'
    image_sha='ffe6203da54deeb6db5d2a98a83f9ec8e55f149d3f7ba622e1abe5fa966ee3d6'
    boot_attempts=120
    guest_groups='adm, sudo'
    ;;
  el9)
    image_url='https://dl.rockylinux.org/vault/rocky/9.4/images/x86_64/Rocky-9-GenericCloud-Base-9.4-20240609.1.x86_64.qcow2'
    image_sha='2179864f4fa9799f11c0824c439666c2451d6751450494e20034efd4f3fa0559'
    boot_attempts=150
    guest_groups='adm, wheel'
    ;;
  *) echo 'unsupported nohz_full guest profile' >&2; exit 2 ;;
esac

logs="${state}/evidence"
private="${state}/private"
umask 077
mkdir -p "$logs" "$private"
repository="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
revision="$(git -C "$repository" rev-parse HEAD)"
test "$(cat "${binaries}/source-revision")" = "$revision"
(cd "$binaries" && sha256sum -c SHA256SUMS)
(cd "$packages" && sha256sum -c SHA256SUMS)
cp "${binaries}/source-revision" "${binaries}/SHA256SUMS" "$logs/"
cp "${packages}/SHA256SUMS" "${logs}/packages-SHA256SUMS"
cp "${packages}/package-versions.txt" "${packages}/repositories.txt" "$logs/"
printf 'profile=%s\nrevision=%s\nimage=%s\nimage_sha256=%s\nvcpus=2\nmem_mib=3072\n' \
  "$profile" "$revision" "$image_url" "$image_sha" > "${logs}/profile.txt"

# Reuse the ordinary qualification images, CPU/memory shape and boot bounds.
# The EL9 vault requires HTTP/1.1, as in the ordinary EL9 job.
image="${private}/guest.qcow2"
curl --http1.1 --fail --location --retry 3 --output "$image" "$image_url"
printf '%s  %s\n' "$image_sha" "$image" | sha256sum -c -
key="${private}/ssh-key"
ssh-keygen -q -t ed25519 -N '' -C '' -f "$key"
public_key="$(<"${key}.pub")"
printf '%s\n' \
  '#cloud-config' \
  'users:' \
  '  - name: opc' \
  "    groups: [${guest_groups}]" \
  '    shell: /bin/bash' \
  '    sudo: ALL=(ALL) NOPASSWD:ALL' \
  '    lock_passwd: true' \
  '    ssh_authorized_keys:' \
  "      - ${public_key}" \
  'ssh_pwauth: false' \
  'disable_root: true' \
  'package_update: false' > "${private}/user-data"
printf '%s\n' 'instance-id: opc-tft-nohz' 'local-hostname: opc-tft-nohz' \
  > "${private}/meta-data"
cloud-localds "${private}/seed.iso" "${private}/user-data" "${private}/meta-data"
pid_file="${private}/qemu.pid"
cleanup() {
  if sudo test -s "$pid_file"; then
    pid="$(sudo cat "$pid_file")"
    sudo kill "$pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT
if sudo test -c /dev/kvm; then
  machine='accel=kvm'
  cpu='host'
else
  machine='accel=tcg'
  cpu='max'
fi
# Create the serial log as the runner user so failure artifacts stay readable.
: > "${logs}/serial.log"
sudo qemu-system-x86_64 \
  -machine "$machine" -cpu "$cpu" -smp 2 -m 3072 \
  -drive "file=${image},format=qcow2,if=virtio,snapshot=on" \
  -drive "file=${private}/seed.iso,format=raw,media=cdrom,readonly=on" \
  -netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:2229-:22 \
  -device virtio-net-pci,netdev=net0 -display none \
  -serial "file:${logs}/serial.log" -daemonize -pidfile "$pid_file"

ssh_options=(
  -i "$key" -p 2229 -o BatchMode=yes -o ConnectTimeout=2
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
)
wait_for_boot() {
  local previous="$1" current
  for ((_attempt = 0; _attempt < boot_attempts; _attempt++)); do
    if current="$(ssh "${ssh_options[@]}" opc@127.0.0.1 \
      'cat /proc/sys/kernel/random/boot_id' 2>/dev/null)" \
      && [[ -n "$current" && "$current" != "$previous" ]]; then
      printf '%s\n' "$current"
      return 0
    fi
    sleep 2
  done
  echo 'guest did not complete the required boot within its qualification bound' >&2
  return 1
}
old_boot="$(wait_for_boot '')"
printf '%s\n' "$old_boot" > "${logs}/boot-before.txt"

# Complete setup before starting a reboot that can close its SSH transport.
ssh "${ssh_options[@]}" opc@127.0.0.1 bash -s -- "$profile" <<'GUEST'
set -euo pipefail
systemd-detect-virt | grep -Eq '^(kvm|qemu)$'
if [[ "$1" == linux68 ]]; then
  test "$(uname -r)" = 6.8.0-134-generic
  test "$(dpkg-query -W -f='${Version}' linux-image-6.8.0-134-generic)" = 6.8.0-134.134
  printf '%s\n' 'GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} nohz_full=1"' \
    | sudo tee /etc/default/grub.d/99-opc-nohz-full.cfg
  sudo update-grub
else
  grep -q '^ID="rocky"' /etc/os-release
  case "$(uname -r)" in
    5.14.0-427.*el9_4*) ;;
    *) echo 'unexpected EL9 guest kernel'; exit 1 ;;
  esac
  sudo grubby --update-kernel=ALL --args=nohz_full=1
fi
grep -Fx 'CONFIG_NO_HZ_FULL=y' "/boot/config-$(uname -r)"
GUEST

# A shutdown may close SSH before it receives the reboot command's exit status.
# Only this request admits a transport disconnect; the unchanged bounded wait
# must still observe a different boot ID before any qualification can proceed.
reboot_status=0
ssh "${ssh_options[@]}" opc@127.0.0.1 \
  'sudo systemctl reboot --no-block' || reboot_status=$?
printf 'ssh_exit_status=%s\n' "$reboot_status" > "${logs}/reboot-request.txt"
case "$reboot_status" in
  0|255) ;;
  *) echo "guest reboot request failed with SSH status ${reboot_status}" >&2
     exit "$reboot_status" ;;
esac
new_boot="$(wait_for_boot "$old_boot")"
printf '%s\n' "$new_boot" > "${logs}/boot-after.txt"
test "$new_boot" != "$old_boot"

ssh "${ssh_options[@]}" opc@127.0.0.1 bash -s -- "$profile" <<'GUEST' \
  | tee "${logs}/kernel.txt"
set -euo pipefail
uname -r
uname -v
cat /proc/sys/kernel/random/boot_id
cat /proc/cmdline
grep -Fx 'CONFIG_NO_HZ_FULL=y' "/boot/config-$(uname -r)"
systemd-detect-virt | grep -Eq '^(kvm|qemu)$'
if [[ "$1" == linux68 ]]; then
  test "$(uname -r)" = 6.8.0-134-generic
  test "$(dpkg-query -W -f='${Version}' linux-image-6.8.0-134-generic)" = 6.8.0-134.134
else
  grep -q '^ID="rocky"' /etc/os-release
  case "$(uname -r)" in
    5.14.0-427.*el9_4*) ;;
    *) echo 'unexpected EL9 guest kernel'; exit 1 ;;
  esac
fi
nohz_cpus="$(cat /sys/devices/system/cpu/nohz_full)"
printf 'effective_nohz_full=%s\n' "$nohz_cpus"
test "$nohz_cpus" = 1
sudo mountpoint -q /sys/fs/bpf || sudo mount -t bpf bpf /sys/fs/bpf
mkdir -p /tmp/opc-tft-nohz
GUEST

scp -i "$key" -P 2229 -o BatchMode=yes -o ConnectTimeout=2 \
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "${binaries}/datapath" "${binaries}/grace" \
  "${binaries}/source-revision" "${binaries}/SHA256SUMS" \
  opc@127.0.0.1:/tmp/opc-tft-nohz/
scp -r -i "$key" -P 2229 -o BatchMode=yes -o ConnectTimeout=2 \
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "$packages" opc@127.0.0.1:/tmp/opc-tft-nohz-packages
ssh "${ssh_options[@]}" opc@127.0.0.1 \
  'cd /tmp/opc-tft-nohz && sha256sum -c SHA256SUMS && chmod 0755 datapath grace'
ssh "${ssh_options[@]}" opc@127.0.0.1 bash -s -- "$profile" <<'GUEST'
set -euo pipefail
cd /tmp/opc-tft-nohz-packages
sha256sum -c SHA256SUMS
if [[ "$1" == linux68 ]]; then
  sudo dpkg -i wireguard-tools.deb
else
  sudo dnf install -y --disablerepo='*' \
    --repofrompath=opclocal,file:///tmp/opc-tft-nohz-packages \
    --nogpgcheck nftables wireguard-tools
fi
command -v ip tc ethtool nft wg python3
sudo modprobe wireguard
GUEST

# A direct production-map proof must observe a paired kernel RCU call enclosing
# the live non-sleepable reader. The ordinary ARRAY control must observe none.
ssh "${ssh_options[@]}" opc@127.0.0.1 \
  'sudo env OPC_GTPU_RUN_PRIVILEGED=1 /tmp/opc-tft-nohz/grace --ignored --exact linux::reader_grace::tests::map_in_map_grace_waits_for_live_non_sleepable_reader --nocapture --test-threads=1' \
  2>&1 | tee "${logs}/grace.log"
grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "${logs}/grace.log"
grep -Fxq 'OPC_GTPU_MAP_READER_GRACE_PROVEN' "${logs}/grace.log"
grep -Fxq 'OPC_GTPU_MAP_READER_GRACE_NEGATIVE_CONTROL_PROVEN' "${logs}/grace.log"
grep -Fxq 'OPC_GTPU_MAP_READER_GRACE_THREAD_CONTROL_PROVEN' "${logs}/grace.log"

# These exact packet proofs validate the opt-in profile before any
# setup/skip path. They require effective nohz CPUs, GLOBAL absent, and actual
# Aya availability; the shared-PAA test also proves retained bank reuse.
ssh "${ssh_options[@]}" opc@127.0.0.1 \
  'sudo env OPC_GTPU_RUN_PRIVILEGED=1 OPC_GTPU_REQUIRE_NOHZ_FULL=1 unshare -n -- bash -euo pipefail -c "ip link set lo up && exec /tmp/opc-tft-nohz/datapath --ignored --nocapture --test-threads=1 ebpf_gtpu_shared_paa_tft_classifier_ipv4_live_contract ebpf_gtpu_tft_classifier_removal_fence_forwards_default_uplink ebpf_gtpu_tft_classifier_removal_keeps_default_uplink_continuous ebpf_gtpu_tft_fragmented_esp_pair ebpf_gtpu_tft_fragment_affinity_exact_key ebpf_gtpu_tft_fragment_affinity_conflicting_first ebpf_gtpu_tft_fragment_affinity_overlap_and_range_bound ebpf_gtpu_tft_fragment_affinity_classifier_identity ebpf_gtpu_tft_fragment_affinity_lifecycle ebpf_gtpu_tft_fragment_affinity_malformed_retained ebpf_gtpu_tft_fragment_affinity_expiry ebpf_gtpu_tft_fragment_affinity_authority_revocation ebpf_gtpu_tft_fragment_affinity_capacity ebpf_gtpu_tft_fragment_affinity_cross_attachment ebpf_gtpu_tft_fragment_affinity_port_only_control"' \
  2>&1 | tee "${logs}/datapath.log"
if grep -q 'skipping:' "${logs}/datapath.log"; then
  echo 'nohz_full packet proofs skipped instead of running' >&2
  exit 1
fi
grep -Eq '^test result: ok\. 15 passed; 0 failed; 0 ignored;' "${logs}/datapath.log"
for marker in OPC_GTPU_TFT_NOHZ_PROFILE_PROVEN OPC_GTPU_TFT_NOHZ_CAPABILITY_PROVEN; do
  test "$(grep -Fxc "$marker" "${logs}/datapath.log")" = 15
done
for marker in OPC_GTPU_TFT_NOHZ_BANK_REUSE_PROVEN OPC_GTPU_TFT_NOHZ_LIFECYCLE_PROVEN OPC_GTPU_TFT_IPV4_LIVE_PROVEN; do
  test "$(grep -Fxc "$marker" "${logs}/datapath.log")" = 1
done
grep -Fq 'OPC_GTPU_TFT_REMOVAL_FENCE_DEFAULT_PROVEN:' "${logs}/datapath.log"
grep -Fq 'OPC_GTPU_TFT_REMOVAL_CONTINUITY_PROVEN:' "${logs}/datapath.log"
grep -Fxq 'OPC_GTPU_TFT_FRAGMENT_ESP_PAIR_PROVEN' "${logs}/datapath.log"
grep -Fxq 'OPC_GTPU_TFT_FRAGMENT_EXACT_KEY_PROVEN' "${logs}/datapath.log"
grep -Fxq 'OPC_GTPU_TFT_FRAGMENT_CONFLICTING_FIRST_PROVEN' "${logs}/datapath.log"
grep -Fxq 'OPC_GTPU_TFT_FRAGMENT_OVERLAP_AND_RANGE_BOUND_PROVEN' "${logs}/datapath.log"
grep -Fxq 'OPC_GTPU_TFT_FRAGMENT_CLASSIFIER_IDENTITY_PROVEN' "${logs}/datapath.log"
grep -Fxq 'OPC_GTPU_TFT_FRAGMENT_LIFECYCLE_PROVEN' "${logs}/datapath.log"
grep -Fxq 'OPC_GTPU_TFT_FRAGMENT_MALFORMED_RETAINED_PROVEN' "${logs}/datapath.log"
grep -Fxq 'OPC_GTPU_TFT_FRAGMENT_EXPIRY_PROVEN' "${logs}/datapath.log"
grep -Fxq 'OPC_GTPU_TFT_FRAGMENT_AUTHORITY_REVOCATION_PROVEN' "${logs}/datapath.log"
grep -Fxq 'OPC_GTPU_TFT_FRAGMENT_CAPACITY_PROVEN' "${logs}/datapath.log"
grep -Fxq 'OPC_GTPU_TFT_FRAGMENT_CROSS_ATTACHMENT_PROVEN' "${logs}/datapath.log"
grep -Fxq 'OPC_GTPU_TFT_FRAGMENT_PORT_ONLY_CONTROL_PROVEN' "${logs}/datapath.log"
ssh "${ssh_options[@]}" opc@127.0.0.1 \
  'cd /tmp/opc-tft-nohz && sha256sum -c SHA256SUMS' | tee "${logs}/binary-after.txt"
echo 'OPC_GTPU_TFT_NOHZ_VM_QUALIFIED'
