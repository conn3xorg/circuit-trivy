variable "port" {
  type    = number
  default = 2222
}

module "trivy" {
  source = "../.."

  hosts                = { box = "127.0.0.1" }
  ssh_port             = var.port
  ssh_private_key_file = "./id_ed25519"
  ssh_known_hosts_file = "./known_hosts"

  severity = ["HIGH", "CRITICAL"]
  targets  = ["/"]
  schedule = "daily"
  keep     = 4
}

output "summary" {
  value = module.trivy.summary
}
