rule sus_archive_afterfx {
    meta:
  	    author = "Colin Cowie"
        description = "Detects archives with the dll named AfterFX or AfterFXLib"
        references = "https://infosec.exchange/@rmceoin/109763719160050309"
  strings:
        $rar_header = { 52 61 72 21 1A 07 00 }
        $afterfx = {41 66 74 65 72 46 58 [0-3] 2e 64 6c 6c} // This checks for AfterFX[0-3].dll
 
    condition:
        (uint32(0) == 0x04034b50 or $rar_header at 0 ) // check for zip or rar
        and $afterfx
}
