variable "port" {
  type    = number
  default = 2222
}

# CI sets these to install an older Trivy first, then upgrades to the
# circuit's own pin by applying again without them.
variable "trivy_version" {
  type    = string
  default = null
}

variable "checksums" {
  type    = map(string)
  default = null
}

module "trivy" {
  source = "../.."

  hosts                = { box = "127.0.0.1" }
  ssh_port             = var.port
  ssh_private_key_file = "./id_ed25519"
  ssh_known_hosts_file = "./known_hosts"
  trivy_version        = var.trivy_version
  checksums            = var.checksums

  severity = ["HIGH", "CRITICAL"]
  targets  = ["/"]
  schedule = "daily"
  keep     = 4
}

output "summary" {
  value = module.trivy.summary
}
