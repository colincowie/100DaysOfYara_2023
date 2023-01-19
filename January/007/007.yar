rule sus_js_batloader {
  meta:
    author = "Colin Cowie"
    description = "Detects javascript files similar to batloader"
    reference = "https://www.trendmicro.com/en_us/research/23/a/batloader-malware-abuses-legitimate-tools-uses-obfuscated-javasc.html"
  strings:
    $wscript = "ActiveXObject(\"WScript.Shell\")" nocase
    $cmd = "cmd /c " nocase
    $bat = ".bat" nocase
    $sleep = "WScript.Sleep(" nocase
  condition:
    all of them
    and #cmd > 3
    and #bat > 2
    and #sleep > 2
    and filesize < 5KB
}