rule mal_icedid_zip {
  meta:
    author = "Colin Cowie"
    description = "Detects zip files used to drop IcedID malware"
    references = "SHA1: a71d76937a6692ee6a464f647b9cb2f611b2dd45"
  strings:
    $filename_hex = { 53 65 74 75 70 5f 57 69 6e 5f ?? ?? 2d ?? ?? 2d ?? ?? ?? ?? 5f ?? ?? 2d ?? ?? 2d ?? ?? 2e ?? ?? ??}
    // Looks for "Setup_Win_??-??-??_??-??-??.", ie: "Setup_Win_24-01-2023_20-15-51.exe"    
    $exe = ".exe"
    $iso = ".iso"
    $msi = ".msi"
   condition:
    uint32(0) == 0x04034b50 
    and $filename_hex
    and ($exe or $iso or $msi)
}