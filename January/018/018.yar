rule sus_zip_onenote {
  meta:
    author = "Colin Cowie"
    description = "Detects qakbot archives with onenote"
    refrence = "https://twitter.com/Max_Mal_/status/1620423779737567236?s=20"
  strings:
    $onenote_file = { ?? ?? ?? ?? ?? ?? 2e 6f 6e 65 55 54} // Checks for six characters followed by .oneUT 
  condition:
	uint32(0) == 0x04034b50 
    and filesize<160KB
    and $onenote_file
}
