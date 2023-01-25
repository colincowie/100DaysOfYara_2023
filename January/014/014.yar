rule mal_icedid_archives{
  meta:
  	author = "Colin Cowie"
    description = "Detects zip files used to drop IcedID malware"
    references = "https://infosec.exchange/@bencrypted/109746344873648863"
  strings:
    $setup_filename =  { 53 65 74 75 70 5f 57 69 6e 5f ?? ?? 2d ?? ?? 2d ?? ?? ?? ?? 5f ?? ?? 2d ?? ?? 2d ?? ?? 2e [0-6] ?? ?? ??} 
    $IRS_filename = {49 52 53 5f (66|46) 6f 72 6d 5f [4-34] ??}
    $exe = ".exe"
    $iso = ".iso"
    $msi = ".msi"
    $cmd = ".cmd"
    $lnk = ".lnk"
   condition:
    uint32(0) == 0x04034b50 
    and ($setup_filename or $IRS_filename)
	  and ($exe or $iso or $msi or $cmd or $lnk)
}