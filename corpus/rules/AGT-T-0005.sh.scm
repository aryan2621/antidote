; id: AGT-T-0005
; severity: high
; description: Runs code downloaded at run time (curl/wget piped or substituted into an interpreter)
((pipeline
   (command name: (command_name) @src)
   (command name: (command_name) @dst)) @hit
 (#match? @src "^(curl|wget)$")
 (#match? @dst "^(sh|bash|zsh|dash|python|python3|perl|ruby|node)$"))
((command
   name: (command_name) @dst
   argument: (process_substitution (command name: (command_name) @src))) @hit
 (#match? @src "^(curl|wget)$")
 (#match? @dst "^(sh|bash|zsh|dash|python|python3|perl|ruby|node|source|\\.)$"))
((command
   name: (command_name) @dst
   argument: (string (command_substitution (command name: (command_name) @src)))) @hit
 (#match? @src "^(curl|wget)$")
 (#match? @dst "^(eval|sh|bash|zsh)$"))
