rule Emotet_Malware {
    meta:
        description = "Detection rule for Emotet malware"
        author = "Malicious Checker Team"
        date = "2023-04-07"
        reference = "https://bazaar.abuse.ch/browse/tag/emotet/"
        hash = "4f31610131cea3f977e5e58956bf6a6d80df7c7c0ca38deb3941f7c9c2026dd2"
        classification = "MALWARE"
        
    strings:
        // Common strings found in Emotet samples
        $string1 = "GUID" ascii wide
        $string2 = "CryptDecrypt" ascii wide
        $string3 = "GetTimeZoneInformation" ascii wide
        $string4 = "GetUserNameA" ascii wide
        $string5 = "GetComputerNameA" ascii wide
        
        // API calls commonly used by Emotet
        $api1 = "HttpSendRequestA" ascii wide
        $api2 = "CreateMutexA" ascii wide
        $api3 = "CryptGenKey" ascii wide
        $api4 = "InternetOpenA" ascii wide
        
        // Registry operations
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $reg2 = "HKEY_CURRENT_USER\\Software" ascii wide
        
        // Crypto/obfuscation related
        $crypto1 = { 8B 45 ?? 8D 55 ?? E8 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? }
        $crypto2 = { 8B ?? 00 83 ?? 01 33 ?? 39 ?? 75 ?? 39 ?? 75 ?? 89 ?? }
        
    condition:
        // File is PE file and matches necessary conditions
        uint16(0) == 0x5A4D and 
        (
            // Match 3 of the common strings
            3 of ($string*) and 
            // Match at least 2 of the API calls
            2 of ($api*) and
            // Match at least 1 of the registry operations
            1 of ($reg*) and
            // Match at least 1 of the crypto patterns
            1 of ($crypto*)
        )
} 