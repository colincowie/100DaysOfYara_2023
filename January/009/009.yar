rule small_zip_js {
  meta:
    author = "Colin Cowie"
    description = "Attempts to find .zip files containing a JS file"
    reference = "https://kevinwinata.com/blog/zip-header-yara/"
  strings:
    $zip_header = {50 4B 03 04}
    $js = ".js"
    $json = ".json"
    $exe = ".exe"
    $msi = ".msi"
    $dll = ".dll"
    $iso = ".iso"
    $vbs = ".vbs"
    $ps1 = ".ps1"
    $php = ".php"
    $css = ".css"
    $manifest = ".manifest"
    $rdf = ".rdf"
    $xul = ".xul"
  condition:
    filesize<10KB and
    not ($json or $exe or $msi or $dll or $iso or $vbs or $ps1 or $php or $css or $manifest or $rdf or $xul) and
    for any i in (1..#zip_header):
      ($js in (@zip_header[i]+30..@zip_header[i]+30+uint16(@zip_header[i]+26)))
}