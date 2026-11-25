rule MAL_EICAR_Test_File {
  meta:
    description = "The EICAR test file"
  strings:
    $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
  condition:
    $a
}
