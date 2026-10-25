; id: AGT-T-0003
; severity: critical
; description: Sends the whole process environment (every secret in it) over the network
((call_expression function: (_) @f arguments: (arguments) @args) @hit
 (#match? @f "(^fetch$|^axios$|^got$|^request$|\\.(post|put|patch|request|send)$)")
 (#match? @args "process\\.env([^.\\[A-Za-z0-9_]|$)"))
