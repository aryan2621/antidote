; id: AGT-T-0004
; severity: high
; description: Evaluates code that is decoded at runtime (obfuscated payload)
((call_expression function: (identifier) @f arguments: (arguments . (call_expression) @inner)) @hit
 (#match? @f "^(eval|Function)$")
 (#match? @inner "^(atob|String\\.fromCharCode|Buffer\\.from|decodeURIComponent|unescape)"))
((new_expression constructor: (identifier) @f arguments: (arguments (call_expression) @inner)) @hit
 (#eq? @f "Function")
 (#match? @inner "^(atob|String\\.fromCharCode|Buffer\\.from|decodeURIComponent|unescape)"))
