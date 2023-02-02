rule gen_appx_files {
	meta:
        author = "Colin Cowie"
        description = "Detects appx files"
        reference = "https://twitter.com/f0wlsec/status/1481338661824307204"
    strings:
        $header = { 50 4B 03 04 }
        $xml_string = "AppxManifest.xmlPK"
        $ct_xml = "[Content_Types].xmlPK"
        $ci_cat = "AppxMetadata/CodeIntegrity.catPK"
        $signature_string = "AppxSignature.p7xPK"
        $block_map = "AppxBlockMap.xmlPK"

    condition:
        $header at 0 
        and $xml_string and $ct_xml and $ci_cat and $signature_string and $block_map
}
