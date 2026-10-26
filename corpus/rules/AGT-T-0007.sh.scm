; id: AGT-T-0007
; severity: high
; description: Reads SSH keys, cloud credentials or the macOS keychain
((command name: (command_name) @c argument: (_) @a) @hit
 (#match? @c "^(cat|cp|tar|zip|scp|rsync|curl|base64|xxd|gzip)$")
 (#match? @a "(\\.ssh/|\\.aws/|\\.gnupg|\\.kube/config|\\.docker/config|Keychains|Login Data)"))
((command name: (command_name) @c argument: (word) @a) @hit
 (#eq? @c "security")
 (#match? @a "^(find-generic-password|find-internet-password|dump-keychain)$"))
