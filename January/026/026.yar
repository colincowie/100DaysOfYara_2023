import "vt"
rule dll_cobaltstrike_profile {
  meta:
    author = "Colin Cowie"
    description = "Detects DLLs performing a request to a known cobaltstrike mallable C2 profile"
    reference  = "https://github.com/pan-unit42/tweets/blob/master/2023-02-08-IOCs-for-Cobalt-Strike-from-IcedID.txt"
  condition:
    vt.metadata.file_type == vt.FileType.PE_DLL
  	and (
    		for any entry in vt.behaviour.http_conversations : (entry.url contains "/jquery" and entry.url contains ".min.js")
        )
    and filesize<1MB
}