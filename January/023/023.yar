rule onenote_base64_malware {
  meta:
    author = "Colin Cowie"
    description = "Detects OneNote files with base64 encoded powershell"
    reference = "https://github.com/pr0xylife/Qakbot/blob/main/Qakbot_obama237_07.02.2023.txt"
  strings:
  	$file_header = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
    $log_supression = "@echo off" base64
    $download = "powershell (new-object system.net.webclient).downloadfile(" base64
    $rundll = "call ru%1ll32" base64
    $programdata = "C:\\programdata\\" base64    
  condition:
    $file_header at 0
    and 3 of them
    and filesize<1MB
}
