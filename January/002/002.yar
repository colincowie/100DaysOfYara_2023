import "pe"
rule mal_exmatter {
  meta:
    author = "Colin Cowie"
    description = "Detects ExMatter files"
    reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/noberus-blackcat-ransomware-ttps"
  strings:
    $string1 = "sync_enc"
    $string2 = "CreateSocks"
    $string3 = "sync.exe"
  condition:
    pe.is_pe 
    and pe.imports("mscoree.dll")
    and (filesize>800KB and filesize<10MB)
    and 2 of them
}