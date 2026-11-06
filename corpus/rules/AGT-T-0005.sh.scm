; id: AGT-T-0005
; severity: high
; description: Runs code downloaded at run time (curl/wget piped or substituted into an interpreter)
; `curl … | python3 -c 'json.load…'` parses data, so it is skipped unless the -c code also execs/evals
((pipeline
   (command name: (command_name) @src)
   (command name: (command_name) @dst)) @hit
 (#match? @src "^(curl|wget)$")
 (#match? @dst "^(sh|bash|zsh|dash|python|python3|perl|ruby|node)$")
 (#not-match? @hit "\\|\\s*(python3?|node|perl|ruby)\\s+-[ce]\\b"))
((pipeline
   (command name: (command_name) @src)
   (command name: (command_name) @dst)) @hit
 (#match? @src "^(curl|wget)$")
 (#match? @dst "^(python|python3|perl|ruby|node)$")
 (#match? @hit "\\|\\s*(python3?|node|perl|ruby)\\s+-[ce]\\b.*(exec|eval|system|subprocess|child_process|stdin\\.read)"))
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
