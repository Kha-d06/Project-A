/*
 * SENTINEL's built-in YARA rules.
 *
 * Each rule describes a technique rather than a specific malware family, so a
 * match is a warning sign, not proof. The meta fields are shown to users:
 *   title       - one-line description of what was found
 *   explanation - why it matters, in plain language
 *   severity    - critical | high | medium | low | info
 *
 * Operators can add their own rules (for example a community rule set, subject to
 * its licence) by pointing SENTINEL_YARA_RULES_DIR at a directory of .yar files.
 */

rule SENTINEL_PowerShell_Encoded_Command
{
    meta:
        title = "Runs an encoded PowerShell command"
        explanation = "The command is hidden in Base64 so it cannot be read at a glance. Malware uses this to slip past people and simple filters."
        severity = "medium"
    strings:
        $ps = "powershell" nocase
        $enc = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ nocase
    condition:
        $ps and $enc
}

rule SENTINEL_Download_And_Execute
{
    meta:
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

rule SENTINEL_Decode_And_Eval
{
    meta:
        title = "Decodes and executes hidden code"
        explanation = "The file decodes a hidden block of text and runs it. Legitimate scripts rarely need to do this."
        severity = "low"
    strings:
        $js = /eval\s*\(\s*(atob|unescape|String\.fromCharCode)/ nocase
        $py = /exec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads)/
    condition:
        any of them
}

rule SENTINEL_Windows_Script_Host_Execution
{
    meta:
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

rule SENTINEL_HTML_Smuggling
{
    meta:
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

rule SENTINEL_Shortcut_Launches_Interpreter
{
    meta:
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

rule SENTINEL_Credential_Dumping_Tool
{
    meta:
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

rule SENTINEL_Ransom_Note
{
    meta:
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

rule SENTINEL_UPX_Packed
{
    meta:
        title = "Program is compressed with a packer (UPX)"
        explanation = "Packing shrinks a program and hides its contents from simple inspection. Many legitimate tools are packed too, so this is context rather than a warning."
        severity = "info"
    strings:
        $a = "UPX0"
        $b = "UPX1"
    condition:
        uint16(0) == 0x5A4D and $a and $b
}
