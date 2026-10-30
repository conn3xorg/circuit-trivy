output "results_dir" {
  description = "Directory on each host that holds one directory per scan, newest linked as latest."
  value       = local.results_dir
}

output "summary" {
  description = "Count of findings by severity from the latest scan on each host. The reports are beside it."
  value       = "${local.results_dir}/latest/summary.txt"
}

output "reports" {
  description = "JSON report of the latest scan for each target. Each has a table of the same name ending in .txt."
  value       = { for t, r in local.reports : t => "${local.results_dir}/latest/${r}.json" }
}
