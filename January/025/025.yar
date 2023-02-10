rule sus_char_converting {
  meta:
    author = "Colin Cowie"
    description = "Detects small files with conversion technique used by Qakbot"
    reference  = "ec674e92a9d108d67d2cc0f1f2d20579a8ca8ba6e32af1fe0ed8a1067a426586"
  strings:
  	$convert = {7b 5b 63 68 61 72 5d 28 5b 63 6f 6e 76 65 72 74 5d 3a 3a 74 6f 69 6e 74 31 36} // matches {[char]([convert]::toint16
  condition:
  	$convert
    and filesize<190KB
}