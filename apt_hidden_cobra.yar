/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-13
   Identifier: Hidden Cobra
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-164A
*/

/* Rule Set ----------------------------------------------------------------- */

rule HiddenCobra_Rule_1 {
   meta:
      description = "Detects Hidden Cobra Malware"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-164A"
      date = "2017-06-13"
   strings:
      $rsaKey_1 = {7B 4E 1E A7 E9 3F 36 4C DE F4 F0 99 C4 D9 B7 94}
      $rsaKey_2 = {A1 FF F2 97 D3 91 13 9D C0 12 02 E4 4C BB 6C 77}
      $rsaKey_3 = {48 EE 6F 4B 9B 53 60 98 45 A5 28 65 8A 0B F8 39}

   condition:
      all of them
}

/* Prone to False Positives ----------------------------------------
rule HiddenCobra_Rule_2 {
   meta:
      description = "Detects Hidden Cobra Malware"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-164A"
      date = "2017-06-13"
   strings:
      $STR1 = "Wating" wide ascii fullword
      $STR2 = "Reamin" wide ascii fullword
      $STR3 = "laptos" wide ascii fullword
   condition:
      ( uint16(0) == 0x5A4D or
        uint16(0) == 0xCFD0 or
        uint16(0) == 0xC3D4 or
        uint32(0) == 0x46445025 or
        uint32(1) == 0x6674725C
      ) and all of them
}
*/

rule HiddenCobra_Rule_3 {
   meta:
      description = "Detects Hidden Cobra Malware"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-164A"
      date = "2017-06-13"
   strings:
      $randomUrlBuilder = { 83 EC 48 53 55 56 57 8B 3D ?? ?? ?? ?? 33 C0 C7}
   condition:
      $randomUrlBuilder
}


import "pe"

rule APT_HiddenCobra_GhostSecret_1 {
   meta:
      description = "Detects Hidden Cobra Sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/"
      date = "2018-08-11"
      hash1 = "05a567fe3f7c22a0ef78cc39dcf2d9ff283580c82bdbe880af9549e7014becfc"
   strings:
      $s1 = "%s\\%s.dll" fullword wide
      $s2 = "PROXY_SVC_DLL.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule APT_HiddenCobra_GhostSecret_2 {
   meta:
      description = "Detects Hidden Cobra Sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/"
      date = "2018-08-11"
      hash1 = "45e68dce0f75353c448865b9abafbef5d4ed6492cd7058f65bf6aac182a9176a"
   strings:
      $s1 = "ping 127.0.0.1 -n 3" fullword wide
      $s2 = "Process32" fullword ascii
      $s11 = "%2d%2d%2d%2d%2d%2d" fullword ascii
      $s12 = "del /a \"" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and all of them
}


import "pe"

rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_1 {
   meta:
      description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
      date = "2019-04-13"
      hash1 = "d77fdabe17cdba62a8e728cbe6c740e2c2e541072501f77988674e07a05dfb39"
   strings:
      $s1 = "www.naver.com" fullword ascii
      $s2 = "PolarSSL Test CA0" fullword ascii
   condition:
      filesize < 1000KB and all of them
}

rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_2 {
   meta:
      description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
      date = "2019-04-13"
      hash1 = "70034b33f59c6698403293cdc28676c7daa8c49031089efa6eefce41e22dccb3"
   strings:
      $s1 = "%SystemRoot%\\System32\\svchost.exe -k mdnetuse" fullword ascii
      $s2 = "%s\\hid.dll" fullword ascii
      $s3 = "%Systemroot%\\System32\\" fullword ascii
      $s4 = "SYSTEM\\CurrentControlSet\\services\\%s\\Parameters" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_3 {
   meta:
      description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
      date = "2019-04-13"
      hash1 = "2151c1977b4555a1761c12f151969f8e853e26c396fa1a7b74ccbaf3a48f4525"
      hash2 = "05feed9762bc46b47a7dc5c469add9f163c16df4ddaafe81983a628da5714461"
      hash3 = "ddea408e178f0412ae78ff5d5adf2439251f68cad4fd853ee466a3c74649642d"
   strings:
      $s1 = "Oleaut32.dll" fullword ascii
      $s2 = "Process32NextA" fullword ascii
      $s3 = "Process32FirstA" fullword ascii
      $s4 = "%sRSA key size  : %d bits" fullword ascii
      $s5 = "emailAddress=" fullword ascii
      $s6 = "%scert. version : %d" fullword ascii
      $s7 = "www.naver.com" fullword ascii

      $x1 = "ztretrtireotreotieroptkierert" fullword ascii
      $x2 = "reykfgkodfgkfdskgdfogpdokgsdfpg" fullword ascii
      $x3 = "fjiejffndxklfsdkfjsaadiepwn" fullword ascii
      $x4 = "fgwljusjpdjah" fullword ascii
      $x5 = "udbcgiut.dat" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and (
            1 of ($x*) or
            6 of ($s*)
      )
}
