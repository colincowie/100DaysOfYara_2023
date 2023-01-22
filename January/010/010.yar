rule chrome_loader_macos_script {
  meta:
    author = "Colin Cowie"
    description = "Detect potential Mac OS browser hijacker script used by ChromeLoader"
    reference = "https://www.th3protocol.com/2022/Choziosi-Loader"
  strings:
    $bash = "/bin/bash"
    $osascript = "osascript -e"
    $launchctl = "launchctl load"
    $curl = "curl"
    $chrome = "chrome.extension"
    $ext = "extension.plist"
    $unzip = "uzip"
   condition:
    $bash and 3 of them
    and filesize < 10KB
}