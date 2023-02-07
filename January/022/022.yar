rule sus_onenote_button {
  meta:
    author = "Colin Cowie"
    description = "Detects OneNote files with a click to open message"
  strings:
  	$file_header = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
  	$prompt = "double click \"open\"" wide nocase
  condition:
  	$file_header at 0
    and $prompt
    and filesize<750KB
}
