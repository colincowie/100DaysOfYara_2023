rule sus_lnk_files {
  meta:
    author = "Colin Cowie"
    description = "Yara rule to detect suspicous .LNK files used by IcedID"
    reference = "SHA1: 92ba4c948890d67927afa26727474e563e6d1bdf."

  strings:
    $lnk_header = { 4C 00 00 00 }
    $shell = "shell32.dll" ascii wide
    $cmd = "cmd.exe" ascii wide
    $cmd_file = ".cmd" ascii wide
  condition:  
	  all of them
    and $lnk_header at 0
    and filesize<5KB
}
