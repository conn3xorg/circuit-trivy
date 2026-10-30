variable "hosts" {
  type        = any
  description = "Hosts to configure: a map of names to addresses, or to host objects with an address and optional host_key, user, port, private_key_file or jump_hosts."
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "User to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "known_hosts file to check host keys against. When null, ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run commands as root through sudo."
}

variable "trivy_version" {
  type        = string
  default     = "0.76.1"
  description = "Trivy release to install from GitHub. Change checksums with it."

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.trivy_version))
    error_message = "trivy_version is a release number such as \"0.76.1\"."
  }

  validation {
    condition     = !contains(["0.69.4", "0.69.5", "0.69.6"], var.trivy_version)
    error_message = "Trivy 0.69.4, 0.69.5 and 0.69.6 were published by an attacker. See GHSA-69fq-xp46-6x23."
  }
}

variable "checksums" {
  type        = map(string)
  description = "SHA-256 of the release tarball for each architecture, from the release's trivy_<version>_checksums.txt. Change these with trivy_version."
  default = {
    amd64 = "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0"
    arm64 = "e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f"
  }
}

variable "severity" {
  type        = list(string)
  default     = ["HIGH", "CRITICAL"]
  description = "Severities to report, from UNKNOWN, LOW, MEDIUM, HIGH and CRITICAL."

  validation {
    condition     = length(var.severity) > 0 && alltrue([for s in var.severity : contains(["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"], s)])
    error_message = "severity is a list of one or more of UNKNOWN, LOW, MEDIUM, HIGH and CRITICAL."
  }
}

variable "targets" {
  type        = list(string)
  default     = ["/"]
  description = "Absolute paths to scan, each with a report of its own. The default is the host's whole root filesystem."

  validation {
    condition     = length(var.targets) > 0 && alltrue([for t in var.targets : can(regex("^/[A-Za-z0-9._/-]*$", t))])
    error_message = "targets is a list of one or more absolute paths, using letters, digits and . _ - /."
  }

  # Reports are named for their paths with / as _, so two paths mustn't meet.
  validation {
    condition     = length(distinct([for t in var.targets : replace(trim(t, "/"), "/", "_")])) == length(var.targets)
    error_message = "Two of targets would write to the same report. Paths that differ only in / and _ can't be told apart."
  }
}

variable "skip_dirs" {
  type        = list(string)
  default     = []
  description = "Directories to leave out of the scan, as absolute paths or globs, such as network mounts or \"/var/lib/containers\"."

  validation {
    condition     = alltrue([for d in var.skip_dirs : can(regex("^/[A-Za-z0-9._/*-]*$", d))])
    error_message = "Each of skip_dirs is an absolute path or glob, using letters, digits and . _ - / *."
  }
}

variable "schedule" {
  type        = string
  default     = "daily"
  description = "When the scan timer runs, as a systemd OnCalendar expression such as \"daily\" or \"Sun 03:00\"."

  validation {
    condition     = !strcontains(var.schedule, "\n") && !strcontains(var.schedule, "'")
    error_message = "schedule is a single-line systemd calendar expression."
  }
}

variable "keep" {
  type        = number
  default     = 7
  description = "Number of scans to keep under /var/lib/conn3x-trivy. Older ones are deleted after each scan."

  validation {
    condition     = var.keep >= 1 && floor(var.keep) == var.keep
    error_message = "keep must be a whole number, 1 or more."
  }
}

variable "run_now" {
  type        = bool
  default     = false
  description = "Scan during the apply: on the first apply, and again whenever the scan's settings change. The first scan downloads Trivy's database."
}
