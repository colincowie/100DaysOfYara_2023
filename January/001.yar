rule sus_zip_vbs {
  meta:
    author = "Colin Cowie"
    description = "Detects .zip file containing a VBS"
    reference = "https://kevinwinata.com/blog/zip-header-yara/"
  strings:
    $zip_header = {50 4B 03 04}
    $vbs_file = ".vbs"
    $lnk_string = "LNK"
  condition:
    filesize<10MB and
    $lnk_string and
    for any i in (1..#zip_header):
      ($vbs_file in (@zip_header[i]+30..@zip_header[i]+30+uint16(@zip_header[i]+26)))
}
