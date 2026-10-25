// Tool-description / skill / prompt poisoning. Each rule has a matching sample in
// crates/antidote-cli/tests/fixtures/bad/<id>.*

rule hidden_unicode_tags {
    meta:
        id = "AGT-R-0001"
        severity = "critical"
        description = "Invisible Unicode tag characters (U+E0000-E007F) can smuggle instructions the user cannot see"
    strings:
        $tag = { F3 A0 (80 | 81) ?? }
    condition:
        // emoji subdivision flags use up to 6 tag chars, hidden text needs more
        #tag >= 8
}

rule bidi_override {
    meta:
        id = "AGT-R-0002"
        severity = "medium"
        description = "Bidirectional override characters can make text display differently from what the model reads"
    strings:
        $bidi = { E2 80 (AA | AB | AC | AD | AE) }
        $iso = { E2 81 (A6 | A7 | A8 | A9) }
    condition:
        any of them
}

rule instruction_override {
    meta:
        id = "AGT-R-0003"
        severity = "medium"
        description = "Text tries to override the agent's earlier instructions"
    strings:
        $a = /(ignore|disregard|forget) (all |any )?(of )?(the |your )?(previous|prior|above|earlier|system) (instructions|directions|rules|prompts?)/ nocase
    condition:
        $a
}

rule conceal_from_user {
    meta:
        id = "AGT-R-0004"
        severity = "high"
        description = "Instructs the agent to hide actions from the user"
    strings:
        $a = /(do not|don't|never|without) (tell|telling|inform|informing|mention|mentioning|reveal|revealing|notify|notifying|alert|alerting|show|showing)[^.\n]{0,40}\b(the )?user/ nocase
        // concealment alone is common in benign skills ("don't show the user your scratch work")
        $act = /\b(read|send|upload|copy|forward|post|attach|include)\w*\s[^.\n]{0,40}(files?|keys?|passwords?|tokens?|credentials?|secrets?|ssh|\.env|cookies?|emails?)/ nocase
    condition:
        for any i in (1..#a): ($act in (@a[i] - 300..@a[i] + 300))
}

rule directive_tag_with_secret_access {
    meta:
        id = "AGT-R-0005"
        severity = "critical"
        description = "Hidden directive block (<IMPORTANT>/<SYSTEM>) that points the agent at credentials or config files"
    strings:
        $tag = /<(IMPORTANT|SYSTEM|instructions?|secret)>/ nocase
        $s1 = "~/.ssh" nocase
        $s2 = "id_rsa"
        $s3 = "id_ed25519"
        $s4 = ".aws/credentials"
        $s5 = "mcp.json"
        $s6 = ".env" fullword
        $s7 = "claude_desktop_config.json"
    condition:
        for any i in (1..#tag): (any of ($s*) in (@tag[i]..@tag[i] + 200))
}
