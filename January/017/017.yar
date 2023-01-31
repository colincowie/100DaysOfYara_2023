rule mal_zip_gootloader {
    meta:
  	    author = "Colin Cowie"
        description = "Detects gootloader archives"
        references = "https://www.mandiant.com/resources/blog/tracking-evolution-gootloader-operations"
  strings:
        $js_filename = {5f [0-64] 5f [0-64] 5f [0-64] 2e 6a 73} // _[0-64]_[0-64]_[0-64].js
        $json = ".json"
        $js = ".js"
        $manifest = ".manifest"
        $html = ".html"
        $css = ".css"
        $php = ".php"
    condition:
        (uint32(0) == 0x04034b50) // check for zip file header
        and filesize<150KB
        and $js_filename
        and #js<3 // check for multiple js files
        and not ($json or $css or $html or $manifest or $php) // check for other files commonly found with js scripts
}