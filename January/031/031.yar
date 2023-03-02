rule pdf_with_firebase_zip_link {
  meta:
    author = "Colin Cowie"
    description = "Detects shortcut PDF with firebase zip link"
    reference  = "2"
  strings:
    $pdf_header = {25 50 44 46}
  	$firebase = "firebasestorage.googleapis.com"
    $zip = ".zip"
  condition:
    $pdf_header at 0
    and all of them
}