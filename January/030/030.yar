rule sus_url_shortcut_bat {
  meta:
    author = "Colin Cowie"
    description = "Detects shortcut url files"
    reference  = "https://isc.sans.edu/diary/29592"
  strings:
  	$s1 = "[InternetShortcut]" // matches abc
    $s2 = "URL="
    $s3 = ".bat"

  condition:
  	$shortcut at 0
    and all of them
    and filesize<1KB
}