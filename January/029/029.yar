rule sus_transfersh_scripting {
  meta:
    author = "Colin Cowie"
    description = "Detects transfer.sh usage with output suppression"
    reference  = "f02512e7e2950bdf5fa0cd6fa6b097f806e1b0f6a25538d3314c793998484220"
  strings:
  	$echooff = "@echo off"
    $bitsadmin = "bitsadmin"
    $curl = "curl"
    $wget = "wget"
    $transfer = "transfer.sh" 
  condition:
  	$echooff
    and ($curl or $wget or $bitsadmin)
    and $transfer
    and filesize<800KB
}