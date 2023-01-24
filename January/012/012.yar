rule zip_with_exe_langpack {
  meta:
    author = "Colin Cowie"
    description = "Detects zip archives with a compressed exe and a language pack"
  strings:
    $exe = ".exe"
    $langs = "langs/"
    $ini = ".ini"
   condition:
    uint32(0) == 0x04034b50 
    and all of them
    and #ini > 6
}