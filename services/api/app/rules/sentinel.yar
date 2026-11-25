/*
 * Qalaa's built-in YARA rules.
 *
 * Each rule describes a technique rather than a specific malware family, so a
 * match is a warning sign, not proof. The meta fields are shown to users:
 *   title       - one-line description of what was found
 *   explanation - why it matters, in plain language
 *   severity    - critical | high | medium | low | info
 *
 * Operators can add their own rules (for example a community rule set, subject to
 * its licence) by pointing SENTINEL_YARA_RULES_DIR at a directory of .yar files.
 *
 * Naming and meta follow signature-base conventions (tests/test_rule_hygiene.py
 * enforces them): a prefix saying what a match means, then platform and detail.
 *   MAL_  malware      SUSP_  suspicious technique   HKTL_  hacking tool
 *   PUA_  unwanted     INFO_  worth knowing, not a threat on its own
 * and every rule has id (UUID), author, date, modified, reference, score (0-100).
 */

rule SUSP_PowerShell_Encoded_Command
{
    meta:
        id = "d0f91436-48de-5dda-ab39-347224c0aaaa"
        author = "Qalaa"
        date = "2026-11-16"
        modified = "2026-11-25"
        reference = "https://attack.mitre.org/techniques/T1027/010/"
        score = 60
        title = "Runs an encoded PowerShell command"
        explanation = "The command is hidden in Base64 so it cannot be read at a glance. Malware uses this to slip past people and simple filters."
        severity = "medium"
    strings:
        $ps = "powershell" nocase
        $enc = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ nocase
    condition:
        $ps and $enc
}

rule SUSP_Download_And_Execute
{
    meta:
        id = "4a12a282-6a1e-50a4-8871-7eaa6fc5440f"
        author = "Qalaa"
        date = "2026-11-16"
        modified = "2026-11-25"
        reference = "https://attack.mitre.org/techniques/T1105/"
        score = 65
        title = "Downloads and immediately runs code from the internet"
        explanation = "This pattern fetches a second program or script and runs it straight away, which is how many infections are delivered."
        severity = "medium"
    strings:
        $iex = /(iex|invoke-expression)[^\n]{0,80}(downloadstring|invoke-webrequest|iwr)/ nocase
        $pipe = /(curl|wget)[^\n|]{0,200}\|\s*(ba)?sh\b/ nocase
        $dl = /(downloadstring|downloadfile)\s*\(/ nocase
    condition:
        any of them
}

rule SUSP_Script_Decode_And_Eval
{
    meta:
        id = "3195bb81-27ae-5a6e-990a-1524530e632c"
        author = "Qalaa"
        date = "2026-11-16"
        modified = "2026-11-25"
        reference = "https://attack.mitre.org/techniques/T1140/"
        score = 55
        title = "Decodes and executes hidden code"
        explanation = "The file decodes a hidden block of text and runs it. Legitimate scripts rarely need to do this."
        severity = "low"
    strings:
        $js = /eval\s*\(\s*(atob|unescape|String\.fromCharCode)/ nocase
        $py = /exec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads)/
    condition:
        any of them
}

rule SUSP_WSH_Script_Execution
{
    meta:
        id = "350c0b75-3116-5daf-be7b-44f9b1b385ee"
        author = "Qalaa"
        date = "2026-11-16"
        modified = "2026-11-25"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
        score = 55
        title = "Uses Windows scripting objects to run commands"
        explanation = "The script creates Windows objects that can run programs. This is common in malicious email attachments."
        severity = "low"
    strings:
        $a = "WScript.Shell" nocase
        $b = "Shell.Application" nocase
        $c = /ActiveXObject\s*\(/ nocase
        $run = /\.(Run|Exec|ShellExecute)\s*\(/ nocase
    condition:
        any of ($a, $b, $c) and $run
}

rule SUSP_HTML_Smuggling
{
    meta:
        id = "4a7ffae5-7596-5d79-9d39-af0459afa3d2"
        author = "Qalaa"
        date = "2026-11-16"
        modified = "2026-11-25"
        reference = "https://attack.mitre.org/techniques/T1027/006/"
        score = 60
        title = "Web page builds and downloads a file by itself"
        explanation = "The page assembles a file inside the browser and saves it, a technique used to deliver malware past email and web filters."
        severity = "medium"
    strings:
        $html = "<html" nocase
        $blob = "new Blob" nocase
        $decode = /atob\s*\(|Uint8Array/
        $save1 = "msSaveOrOpenBlob" nocase
        $save2 = /\.download\s*=/
    condition:
        $html and $blob and $decode and any of ($save*)
}

rule SUSP_LNK_Launches_Interpreter
{
    meta:
        id = "7e1d2476-783f-5a74-a0fe-3e705a6b8e52"
        author = "Qalaa"
        date = "2026-11-16"
        modified = "2026-11-25"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
        score = 65
        title = "Shortcut file launches a command interpreter"
        explanation = "This Windows shortcut starts PowerShell, the command prompt or a script host instead of opening a document."
        severity = "high"
    strings:
        $ps = "powershell" wide ascii nocase
        $cmd = "cmd.exe" wide ascii nocase
        $mshta = "mshta" wide ascii nocase
        $wscript = "wscript" wide ascii nocase
    condition:
        uint32(0) == 0x0000004C and any of them
}

rule HKTL_Credential_Dumping_Tool
{
    meta:
        id = "647c070b-e15f-51ea-adb4-744391ba2fb1"
        author = "Qalaa"
        date = "2026-11-16"
        modified = "2026-11-25"
        reference = "https://attack.mitre.org/techniques/T1003/"
        score = 80
        title = "Contains a password-stealing tool"
        explanation = "The file contains commands from tools designed to extract saved passwords and login sessions from Windows."
        severity = "high"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "lsadump::sam" ascii wide nocase
        $c = "privilege::debug" ascii wide nocase
    condition:
        2 of them
}

rule SUSP_Ransom_Note
{
    meta:
        id = "543c1748-11be-57bb-82ab-a2095ed5f840"
        author = "Qalaa"
        date = "2026-11-16"
        modified = "2026-11-25"
        reference = "https://attack.mitre.org/techniques/T1486/"
        score = 70
        title = "Contains wording typical of a ransom note"
        explanation = "The text tells the reader their files are encrypted and demands payment. That is characteristic of ransomware."
        severity = "medium"
    strings:
        $enc = /your (personal )?files (have been|are) encrypted/ nocase ascii wide
        $pay1 = "bitcoin" nocase ascii wide
        $pay2 = "decrypt" nocase ascii wide
    condition:
        $enc and any of ($pay*)
}

rule INFO_UPX_Packed
{
    meta:
        id = "a9249751-c0aa-5f0d-8e36-bd6b3cdc45ee"
        author = "Qalaa"
        date = "2026-11-16"
        modified = "2026-11-25"
        reference = "https://attack.mitre.org/techniques/T1027/002/"
        score = 20
        title = "Program is compressed with a packer (UPX)"
        explanation = "Packing shrinks a program and hides its contents from simple inspection. Many legitimate tools are packed too, so this is context rather than a warning."
        severity = "info"
    strings:
        $a = "UPX0"
        $b = "UPX1"
    condition:
        uint16(0) == 0x5A4D and $a and $b
}
