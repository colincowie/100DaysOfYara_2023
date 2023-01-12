rule file_format_onenote {
  meta:
    author = "Colin Cowie"
    description = "Detects onenote"
  strings:
  	$file_header = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
  condition:
	$file_header at 0
}