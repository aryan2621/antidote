; id: AGT-T-0001
; severity: medium
; description: Runs a shell command built from a dynamic string (command injection / staged payload)
((call
  function: (attribute object: (identifier) @m attribute: (identifier) @f)
  arguments: (argument_list . [(string (interpolation)) (binary_operator)])) @hit
 (#eq? @m "os")
 (#match? @f "^(system|popen)$"))
((call
  function: (attribute object: (identifier) @m)
  arguments: (argument_list . [(string (interpolation)) (binary_operator)] (keyword_argument name: (identifier) @k value: (true)))) @hit
 (#eq? @m "subprocess")
 (#eq? @k "shell"))
