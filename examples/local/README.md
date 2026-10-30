# Local example

Applies circuit-trivy to a throwaway Rocky Linux 10 container with systemd, reporting HIGH and CRITICAL findings across its root filesystem. You need Conn3x and Podman.

```sh
./up.sh
conn3x init
conn3x apply
conn3x plan
```

The second plan says `No changes.` The apply sets up the daily timer but doesn't scan. To run a scan now and see the counts:

```sh
ssh -p 2222 -i id_ed25519 -o UserKnownHostsFile=known_hosts root@127.0.0.1 'systemctl start conn3x-trivy.service; cat /var/lib/conn3x-trivy/latest/summary.txt'
```

The first scan downloads Trivy's database, which takes 1.6 GB under `/var/cache/conn3x-trivy`. To read the findings:

```sh
ssh -p 2222 -i id_ed25519 -o UserKnownHostsFile=known_hosts root@127.0.0.1 cat /var/lib/conn3x-trivy/latest/root.txt
```

Want to watch it catch something? `check.sh` plants a copy of lodash 4.17.4 under `/opt`, scans, and checks the report names CVE-2019-10744. It also checks the scan wrote nothing outside its own directories, then removes the plant:

```sh
podman exec -i circuit-trivy sh < check.sh
```

`up.sh` listens on `127.0.0.1:2222`. Set `PORT` to use another port, and pass the same port to Conn3x with `-var port=PORT`. Set `CONTAINERFILE` to test another distro, such as one of the images in Conn3x's `test/images`, which CI uses. On a Mac, rootful Podman is simplest: `export CONTAINER_CONNECTION=podman-machine-default-root`.

A container isn't a good place to judge the sandbox: systemd there can't always set up the read-only view of the host, and carries on without it. See the main README.

`./down.sh` removes the container, its volumes, the key and the state.
