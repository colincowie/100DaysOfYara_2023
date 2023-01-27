rule sus_cracks_archive {
    meta:
  	    author = "Colin Cowie"
        description = "Detects archives used for cracked software"
        references = "https://blog.xorhex.com/blog/onehundreddiscontiguousdaysofyara-day6/"
  strings:
        $rar_header = { 52 61 72 21 1A 07 00 }
        $cracker = "Cracker.dll" nocase
        $setup = "setup" nocase
    condition:
        (uint32(0) == 0x04034b50 or $rar_header at 0 ) // check for zip or rar
        and $cracker
        and $setup
}