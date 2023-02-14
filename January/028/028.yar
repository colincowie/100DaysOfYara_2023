import "vt"
rule qakbot_detection_gap {
  meta:
    author = "Colin Cowie"
    description = "Detects qakbot Sophos is missing"
  condition:
    // ensure the file is a new file upload on VT and not a rescan
    vt.metadata.new_file 
    // First check if anyone is detecting the file as qakbot 
    and for any engine, signature in vt.metadata.signatures : (
      signature contains "qakbot" or signature contains "QAKBOT" or signature contains "QakBot" or signature contains "QBot"  or signature contains "Qbot"
    )
    // Then check if Sophos isn't detecting it:
    and for any engine, signature in vt.metadata.signatures : (
      engine == "Sophos" and signature == ""
    )
}