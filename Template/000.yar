rule malware_family_Z {
  meta:
    author = "Colin Cowie"
    description = "A brief description of the rule and what it does."
    reference = "A reference or source for the rule, if applicable."
  strings:
    $string1 = "A string or pattern of bytes to search for in the file."
    $string2 = "Another string or pattern of bytes to search for."
    $regex1 = /a regular expression to search for in the file/
    $regex2 = /another regular expression to search for/
  condition:
    all of them
}