rule TestRule {
    meta:
        author = "installer"
        description = "Simple test rule that matches the text 'malware'"
    strings:
        $mal = "malware"
    condition:
        $mal
}