# Facts give each host's architecture, which picks the release tarball, and
# its distribution. Trivy has no vulnerability data for Fedora's packages and
# would report a Fedora host clean, so a host it can't judge stops here.
data "conn3x_host" "facts" {
  for_each = var.hosts

  ssh {
    host             = try(each.value.address, each.value)
    host_key         = try(each.value.host_key, null)
    user             = try(each.value.user, var.ssh_user)
    port             = try(each.value.port, var.ssh_port)
    private_key_file = try(each.value.private_key_file, var.ssh_private_key_file)
    jump_hosts       = try(each.value.jump_hosts, null)
    known_hosts_file = var.ssh_known_hosts_file
  }

  lifecycle {
    postcondition {
      condition     = (self.os_id == "ubuntu" && self.os_version == "24.04") || (self.os_id == "debian" && self.os_version == "13") || (self.os_id == "rocky" && startswith(self.os_version, "10."))
      error_message = "Host ${each.key} runs ${self.os_id} ${self.os_version}. This circuit supports Ubuntu 24.04, Debian 13 and Rocky Linux 10."
    }
  }
}

locals {
  release = { x86_64 = "64bit", aarch64 = "ARM64" }
  goarch  = { x86_64 = "amd64", aarch64 = "arm64" }

  home        = "/opt/trivy/${var.trivy_version}"
  tarball     = "/opt/trivy/trivy_${var.trivy_version}.tar.gz"
  results_dir = "/var/lib/conn3x-trivy"
  cache_dir   = "/var/cache/conn3x-trivy"
  script      = "/usr/local/sbin/conn3x-trivy"
  unit        = "conn3x-trivy"

  # Trivy would otherwise read its own database and earlier reports as part
  # of the host.
  skip_dirs = join(",", concat([local.results_dir, local.cache_dir], var.skip_dirs))

  # Each report is named for its path, with "/" itself as root.
  reports = { for t in var.targets : t => t == "/" ? "root" : replace(trim(t, "/"), "/", "_") }

  run_script = <<-EOT
    #!/bin/sh
    # Written by Conn3x. Changes here are overwritten on the next apply.
    # Scans ${join(" ", var.targets)} for vulnerabilities and writes the reports
    # to a new directory under ${local.results_dir}, then points latest at it.
    set -eu
    umask 077
    dir=${local.results_dir}
    run=$(date -u +%Y%m%dT%H%M%SZ)
    mkdir -p "$dir/$run"
    scan() {
      /usr/local/bin/trivy rootfs \
        --cache-dir ${local.cache_dir} \
        --scanners vuln \
        --severity ${join(",", var.severity)} \
        --skip-dirs ${local.skip_dirs} \
        --list-all-pkgs=false \
        --timeout 2h \
        --no-progress \
        --format json \
        --output "$dir/$run/$2.json" \
        "$1" >> "$dir/$run/trivy.log" 2>&1 || {
          tail -n 20 "$dir/$run/trivy.log" >&2
          exit 1
        }
      /usr/local/bin/trivy convert --format table --output "$dir/$run/$2.txt" "$dir/$run/$2.json" >> "$dir/$run/trivy.log" 2>&1
    }
    %{for t, r in local.reports~}
    scan ${t} ${r}
    %{endfor~}
    # Trivy exits 0 whatever it finds, so a failed unit always means a failed
    # scan. "Severity" appears once per finding in the JSON.
    cat "$dir/$run"/*.json | sed -n 's/.*"Severity": "\([A-Z]*\)".*/\1/p' | sort | uniq -c | awk '{ print $2, $1 }' > "$dir/$run/summary.txt"
    ln -sfn "$run" "$dir/latest"
    find "$dir" -mindepth 1 -maxdepth 1 -type d -name '2*' | sort | head -n -${var.keep} | xargs -r rm -rf
    cat "$dir/$run/summary.txt"
  EOT
}

circuit "trivy" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "tools" {
    for_each = toset(["curl", "tar", "gzip"])
    package {
      name = item.value
    }
  }

  # The tarball from the release, not Aqua's apt or rpm repository or its
  # install script: a version and a checksum fixed here can't change under
  # you, as those channels did in March 2026 (GHSA-69fq-xp46-6x23).
  step "download" {
    download {
      url    = "https://github.com/aquasecurity/trivy/releases/download/v${var.trivy_version}/trivy_${var.trivy_version}_Linux-${local.release[data.conn3x_host.facts[each.key].arch]}.tar.gz"
      sha256 = var.checksums[local.goarch[data.conn3x_host.facts[each.key].arch]]
      dest   = local.tarball
    }
  }

  step "unpack" {
    archive {
      src     = local.tarball
      dest    = local.home
      creates = "${local.home}/trivy"
    }
  }

  step "link" {
    link {
      path   = "/usr/local/bin/trivy"
      target = "${local.home}/trivy"
    }
  }

  # Reports list every known hole in the host, so only root reads them.
  step "results_dir" {
    directory {
      path = local.results_dir
      mode = "0700"
    }
  }

  step "cache_dir" {
    directory {
      path = local.cache_dir
      mode = "0700"
    }
  }

  step "script" {
    file {
      path    = local.script
      content = local.run_script
      mode    = "0755"
    }
  }

  step "schedule_valid" {
    command {
      command = "echo 'schedule is not a calendar expression systemd understands: ${var.schedule}' >&2; exit 1"
      unless  = "systemd-analyze calendar '${var.schedule}' >/dev/null"
    }
  }

  # The scan runs as root so it can read everything. This holds it to
  # reading: the whole host is read-only to it but its own two directories,
  # and the one capability it keeps is reading past file permissions.
  step "sandbox" {
    file {
      path    = "/etc/systemd/system/${local.unit}.service.d/sandbox.conf"
      content = <<-EOT
        [Service]
        ProtectSystem=strict
        ReadWritePaths=${local.results_dir} ${local.cache_dir}
        PrivateTmp=true
        NoNewPrivileges=true
        CapabilityBoundingSet=CAP_DAC_READ_SEARCH
        Nice=19
        IOSchedulingClass=idle
      EOT
    }
  }

  step "sandbox_applied" {
    command {
      command  = "systemctl daemon-reload"
      triggers = { sandbox = conn3x_file.trivy__sandbox[each.key].revision }
    }
  }

  step "timer" {
    timer {
      name        = local.unit
      description = "Trivy vulnerability scan"
      on_calendar = var.schedule
      command     = local.script
      persistent  = true
    }
  }

  step "scan" {
    for_each = toset(var.run_now ? ["scan"] : [])
    command {
      command  = "systemctl start ${local.unit}.service"
      triggers = { script = conn3x_file.trivy__script[each.key].revision }
    }
  }
}
