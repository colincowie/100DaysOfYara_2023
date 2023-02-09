rule onenote_zbuild_malware {
  meta:
    author = "Colin Cowie"
    description = "Detects OneNote files with the zbuild file path"
    reference = "https://news.sophos.com/en-us/2023/02/06/qakbot-onenote-attacks/"
  strings:
  	$file_header = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
    $zbuild = "Z:\\build\\" wide
    $hta= ".hta" wide  
    $cmd = ".cmd" wide
    $ps1 = ".ps1" wide
    $vbs = ".vbs" wide
  condition:
    $file_header at 0
    and $zbuild
    and ($hta or $cmd or $ps1 or $vbs)
    and filesize<1MB
}
