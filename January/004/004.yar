rule sus_onenote_scripting {
  meta:
    author = "Colin Cowie"
    description = "Detects OneNote files with script usage"
  strings:
  	$file_header = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
    $vbs = "VBScript" nocase
    $wscript = "WScript.Shell"  nocase
    $script_tag ="<script " nocase
  condition:
  (
    $vbs or $wscript or $script_tag
  ) and
	$file_header at 0
}