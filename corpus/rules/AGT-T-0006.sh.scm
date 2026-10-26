; id: AGT-T-0006
; severity: high
; description: Decodes a base64 blob and pipes it into a shell or interpreter (hidden payload)
((pipeline
   (command name: (command_name) @b argument: (word) @flag)
   (command name: (command_name) @dst)) @hit
 (#eq? @b "base64")
 (#match? @flag "^(-d|-D|--decode)$")
 (#match? @dst "^(sh|bash|zsh|dash|python|python3|perl|ruby|node)$"))
