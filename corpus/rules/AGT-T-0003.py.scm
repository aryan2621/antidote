; id: AGT-T-0003
; severity: critical
; description: Sends the whole process environment (every secret in it) over the network
((call function: (_) @f arguments: (argument_list) @args) @hit
 (#match? @f "(^urlopen$|\\.(post|put|patch|request|urlopen|send|sendall)$)")
 (#match? @args "os\\.environ([^.\\[A-Za-z0-9_]|$)"))
