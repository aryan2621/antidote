; id: AGT-T-0002
; severity: high
; description: Reads SSH keys, cloud credentials, keychains or browser profiles
((call_expression
  function: [(identifier) @f (member_expression property: (property_identifier) @f)]
  arguments: (arguments) @args) @hit
 (#match? @f "^(readFile|readFileSync|createReadStream|readdir|readdirSync|copyFile|copyFileSync)$")
 (#match? @args "(\\.ssh|\\.aws|\\.gnupg|\\.kube|\\.docker|gcloud|Keychains|Login Data|Google/Chrome|BraveSoftware|Firefox/Profiles)"))
