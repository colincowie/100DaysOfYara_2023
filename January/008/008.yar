rule sus_lnk_files {
  meta:
    author = "Colin Cowie"
    description = "Yara rule to detect suspicious .LNK files"
    reference = "https://github.com/Cisco-Talos/IOCs/blob/main/2023/01/following-the-lnk-metadata-trail.txt"
  strings:
    $lnk_header = { 4C 00 00 00 }
    $andand = " && " ascii wide
  condition:  
    $lnk_header at 0
    and #andand > 2
    and filesize < 5KB
}