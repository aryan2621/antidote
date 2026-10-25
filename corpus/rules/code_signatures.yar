// Malicious code / install-instruction patterns seen in poisoned skills and MCP packages.
// Each rule has a matching sample in crates/antidote-cli/tests/fixtures/bad/<id>.*

rule credential_exfiltration {
    meta:
        id = "AGT-R-0101"
        severity = "critical"
        description = "Reads credential files and sends data to a webhook / paste / tunnel endpoint"
    strings:
        $c1 = "~/.ssh" nocase
        $c2 = "id_rsa"
        $c3 = ".aws/credentials"
        $c4 = "find-generic-password"
        $c5 = "Login Data"
        $c6 = "wallet.dat"
        $n1 = "webhook.site"
        $n2 = "discord.com/api/webhooks"
        $n3 = "api.telegram.org/bot"
        $n4 = "pastebin.com"
        $n5 = "ngrok"
        $n6 = "pipedream.net"
        $n7 = "requestbin"
    condition:
        any of ($c*) and any of ($n*)
}

rule pipe_to_shell {
    meta:
        id = "AGT-R-0102"
        severity = "medium"
        description = "Downloads a script and pipes it straight into a shell"
    strings:
        $a = /(curl|wget)[^\n|;]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b/
    condition:
        $a
}

rule encoded_exec {
    meta:
        id = "AGT-R-0103"
        severity = "critical"
        description = "Decodes a base64 payload and executes it"
    strings:
        $sh = /base64\s+(-d|--decode|-D)[^\n]{0,60}\|\s*(ba|z)?sh\b/
        $py = /exec\(\s*(base64\.)?b64decode\(/
        $js = /eval\(\s*(atob|Buffer\.from)\(/
    condition:
        any of them
}

rule reverse_shell {
    meta:
        id = "AGT-R-0104"
        severity = "critical"
        description = "Reverse shell one-liner"
    strings:
        $a = /(ba)?sh -i\s*>&\s*\/dev\/tcp\//
        $b = /\bnc(at)?\s+(-\w+\s+)*-(e|c)\s+\/bin\/(ba|z)?sh/
        $c = "pty.spawn(\"/bin/"
    condition:
        any of them
}

rule quarantine_bypass {
    meta:
        id = "AGT-R-0105"
        severity = "high"
        description = "Strips macOS Gatekeeper quarantine from a downloaded file (ClawHavoc-style stealer delivery)"
    strings:
        $a = /xattr\s+-\w*[dr]\w*\s+(-\w+\s+)*com\.apple\.quarantine/
    condition:
        $a
}
