#!/usr/bin/env sh
# Runs on the host: plants a package with a known hole, scans through the
# timer's service, and checks that the report names the hole, holds only the
# severities asked for, and that the scan wrote nothing outside its own
# directories. CI pipes it in with podman exec.
set -eu
systemctl is-enabled conn3x-trivy.timer

plant=/opt/conn3x-trivy-check/node_modules/lodash
mkdir -p "$plant"
echo '{"name":"lodash","version":"4.17.4"}' > "$plant/package.json"
marker=/root/conn3x-trivy-check.marker
touch "$marker"
sleep 1

systemctl start conn3x-trivy.service

d=/var/lib/conn3x-trivy/latest
cat "$d/summary.txt"
grep -q CVE-2019-10744 "$d/root.json"
grep -q CVE-2019-10744 "$d/root.txt"
grep -q opt/conn3x-trivy-check "$d/root.json"
if grep -qE '"Severity": "(LOW|MEDIUM|UNKNOWN)"' "$d/root.json"; then
  echo "The report holds a severity that wasn't asked for." >&2
  exit 1
fi

changed=$(find / -xdev -type f -newer "$marker" \
  -not -path '/var/lib/conn3x-trivy/*' -not -path '/var/cache/conn3x-trivy/*' \
  -not -path '/var/log/*' -not -path '/var/lib/systemd/*' -not -path '/run/*' -not -path '/tmp/*' -not -path '/var/tmp/*')
if [ -n "$changed" ]; then
  echo "The scan changed files on the host:" >&2
  echo "$changed" >&2
  exit 1
fi

rm -rf /opt/conn3x-trivy-check "$marker"
