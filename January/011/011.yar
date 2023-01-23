import "pe"
rule sus_browser_wallet_stealer {
  meta:
    author = "Colin Cowie"
    description = "Detect binaries mentioning high risk browser extensions"
    reference = "https://www.team-cymru.com/post/darth-vidar-the-dark-side-of-evolving-threat-infrastructure"
  strings:
    $Opera  = "gojhcdgcpbpfigcaejpfhfegekdgiblk" // Opera Wallet
    $Tronium = "pnndplcbkakcplkjnolgbkdgjikjednm" // Tronium
    $Trust = "egjidjbpglichdcondbcbdnbeeppgdph" // Trust Wallet
    $Exodus  = "aholpfdialjgjfhomihkjbmgjidlcdno" // Exodus Web3 Wallet
    $Braavos = "jnlgamecbpmbajjfhmmmlhejkemejdma" // Braavos
    $Enkrypt = "kkpllkodjeloidieedojogacfhpaihoh" // Enkrypt
    $OKX = "mcohilncbfahbmgdjkbpemcciiolgcge" // OKX Web3 Wallet
    $Sender = "epapihdplajcdnnkdeiahlgigofloibg" // Sender
    $Hashpack = "gjagmgiddbbciopjhllkdnddhcglnemk" // Hashpack
    $Eternl = "kmhcihpebfmpgmihbkipmjlmmioameka" // Eternl
    $Gero = "bgpipimickeadkjlklgciifhnalhdjhe" // GeroWallet
    $Pontem  = "phkbamefinggmakgklpkljjmgibohnba" // Pontem Wallet
    $Petra  = "ejjladinnckdgjemekebdpeokbikhfci" // Petra Wallet
    $Martian  = "efbglgofoippbgcjepnhiblaibcnclgk" // Martian Wallet
    $Finnie = "cjmkndjhnagcfbpiemnkdpomccnjblmj" // Finnie
    $Leap  = "aijcbedoijmgnlmjeegjaglmepbmpkpi" // Leap Terra
    $AutoFill = "fiedbfgcleddlbcmgdigjgdfcggjcion" // Microsoft AutoFill
    $Bitwarden = "nngceckbapebfimnlniiiahkandclblb" // Bitwarden
    $KeePass  = "fmhmiaejopepamlcjkncpgpdjichnecm" // KeePass Tusk
    $KeePassXC = "oboonakemofpalcgghocfoadofidjkkk" // KeePassXC-Browser
   condition:
    10 of them
    and pe.is_pe

}