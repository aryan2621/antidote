; id: AGT-T-0001
; severity: medium
; description: Runs a shell command built from a dynamic string (command injection / staged payload)
((call_expression
  function: (identifier) @f
  arguments: (arguments . [(template_string (template_substitution)) (binary_expression)])) @hit
 (#match? @f "^(exec|execSync)$"))
((call_expression
  function: (member_expression object: (_) @o property: (property_identifier) @f)
  arguments: (arguments . [(template_string (template_substitution)) (binary_expression)])) @hit
 (#match? @o "(child_process|^cp$|childProcess)")
 (#match? @f "^(exec|execSync)$"))
