; id: AGT-T-0002
; severity: high
; description: Reads SSH keys, cloud credentials, keychains or browser profiles
((call function: (_) @f) @hit
 (#match? @f "(^open$|^io\\.open$|\\.read_text$|\\.read_bytes$|^shutil\\.copy)")
 (#match? @hit "(\\.ssh|\\.aws|\\.gnupg|\\.kube|\\.docker|gcloud|Keychains|Login Data|Google/Chrome|BraveSoftware|Firefox/Profiles)"))
