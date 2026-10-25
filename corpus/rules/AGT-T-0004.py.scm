; id: AGT-T-0004
; severity: high
; description: Evaluates code that is decoded at runtime (obfuscated payload)
((call function: (identifier) @f arguments: (argument_list . (call) @inner)) @hit
 (#match? @f "^(exec|eval)$")
 (#match? @inner "(b64decode|b32decode|a85decode|decompress|fromhex|unhexlify|codecs\\.decode|marshal\\.loads)"))
