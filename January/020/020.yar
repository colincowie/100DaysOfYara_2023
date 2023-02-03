rule sus_zip_onenote {
    meta:
        author = "Colin Cowie"
        description = "Detects qakbot and IcedID archives with onenote"
        refrence = "https://twitter.com/Max_Mal_/status/1620423779737567236?s=20, 835239c095e966bf6037f5755b0c4ed333a163f5cc19ba0bc50ea3c96e0f1628 "
    strings:
        $qakbot_onenote = { ?? ?? ?? ?? ?? ?? 2e 6f 6e 65 55 54} // Checks for six characters followed by .oneUT 
        $icedid_onenote = { 5f ?? ?? 5f ?? ?? 5f [0-8] 2e 6f 6e 65 } //[_??_??_[0=8].one
    condition:
        uint32(0) == 0x04034b50 
        and filesize<200KB
        and ($qakbot_onenote or $icedid_onenote)
}
