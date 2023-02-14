import "vt"
rule sus_js_msi_download {
  meta:
    author = "Colin Cowie"
    description = "Detects JavaScript files downloading a MSI"
    reference  = "2cd65ad25be03b25c6deb73ddc4697ff39953742"
  condition:	
    vt.metadata.file_type == vt.FileType.JAVASCRIPT	// Check for .js file type
    and for any c in vt.behaviour.http_conversations : (
      c.request_method == vt.Http.Method.GET // Check sandbox network data for a GET request
      and 
      c.url endswith ".msi" //Check for .msi in URL
    )
    and filesize<500KB
}