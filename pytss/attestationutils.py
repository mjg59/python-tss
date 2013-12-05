from pytss import TspiContext
from tspi_defines import *
import tspi_exceptions
import uuid
import M2Crypto
from M2Crypto import m2
import pyasn1
import hashlib
import os
import struct
import base64

well_known_secret = bytearray([0] * 20)
srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')

trusted_certs = { "STM1": """-----BEGIN CERTIFICATE-----
MIIDzDCCArSgAwIBAgIEAAAAATANBgkqhkiG9w0BAQsFADBKMQswCQYDVQQGEwJD
SDEeMBwGA1UEChMVU1RNaWNyb2VsZWN0cm9uaWNzIE5WMRswGQYDVQQDExJTVE0g
VFBNIEVLIFJvb3QgQ0EwHhcNMDkwNzI4MDAwMDAwWhcNMjkxMjMxMDAwMDAwWjBV
MQswCQYDVQQGEwJDSDEeMBwGA1UEChMVU1RNaWNyb2VsZWN0cm9uaWNzIE5WMSYw
JAYDVQQDEx1TVE0gVFBNIEVLIEludGVybWVkaWF0ZSBDQSAwMTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAJQYnWO8iw955vWqakWNr3YyazQnNzqV97+l
Qa+wUKMVY+lsyhAyOyXO31j4+clvsj6+JhNEwQtcnpkSc+TX60eZvLhgZPUgRVuK
B9w4GUVyg/db593QUmP8K41Is8E+l32CQdcVh9go0toqf/oS/za1TDFHEHLlB4dC
joKkfr3/hkGA9XJaoUopO2ELt4Otop12aw1BknoiTh1+YbzrZtAlIwK2TX99GW3S
IjaCi+fLoXyK2Fmx8vKnr9JfNL888xK9BQfhZzKmbKm/eLD1e1CFRs1B3z2gd3ax
pW5j1OIkSBMOIUeip5+7xvYo2gor5mxatB+rzSvrWup9AwIcymMCAwEAAaOBrjCB
qzAdBgNVHQ4EFgQU88kVdKbnc/8TvwxrrXp7Zc8ceCAwHwYDVR0jBBgwFoAUb+bF
bAe3bIsKgZKDXMtBHva00ScwRQYDVR0gAQH/BDswOTA3BgRVHSAAMC8wLQYIKwYB
BQUHAgEWIWh0dHA6Ly93d3cuc3QuY29tL1RQTS9yZXBvc2l0b3J5LzAOBgNVHQ8B
Af8EBAMCAAQwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEA
uZqViou3aZDGvaAn29gghOkj04SkEWViZR3dU3DGrA+5ZX+zr6kZduus3Hf0bVHT
I318PZGTml1wm6faDRomE8bI5xADWhPiCQ1Gf7cFPiqaPkq7mgdC6SGlQtRAfoP8
ISUJlih0UtsqBWGql4lpk5G6YmvAezguWmMR0/O5Cx5w8YKfXkwAhegGmMGIoJFO
oSzJrS7jK2GnGCuRG65OQVC5HiQY2fFF0JePLWG/D56djNxMbPNGTHF3+yBWg0DU
0xJKYKGFdjFcw0Wi0m2j49Pv3JD1f78c2Z3I/65pkklZGu4awnKQcHeGIbdYF0hQ
LtDSBV4DR9q5GVxSR9JPgQ==
-----END CERTIFICATE-----""" ,
                  "STM2": """-----BEGIN CERTIFICATE-----
MIIDzDCCArSgAwIBAgIEAAAAAzANBgkqhkiG9w0BAQsFADBKMQswCQYDVQQGEwJD
SDEeMBwGA1UEChMVU1RNaWNyb2VsZWN0cm9uaWNzIE5WMRswGQYDVQQDExJTVE0g
VFBNIEVLIFJvb3QgQ0EwHhcNMTEwMTIxMDAwMDAwWhcNMjkxMjMxMDAwMDAwWjBV
MQswCQYDVQQGEwJDSDEeMBwGA1UEChMVU1RNaWNyb2VsZWN0cm9uaWNzIE5WMSYw
JAYDVQQDEx1TVE0gVFBNIEVLIEludGVybWVkaWF0ZSBDQSAwMjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAJO3ihn/uHgV3HrlPZpv8+1+xg9ccLf3pVXJ
oT5n8PHHixN6ZRBmf/Ng85/ODZzxnotC64WD8GHMLyQ0Cna3MJF+MGJZ5R5JkuJR
B4CtgTPwcTVZIsCuup0aDWnPzYqHwvfaiD2FD0aaxCnTKIjWU9OztTD2I61xW2LK
EY4Vde+W3C7WZgS5TpqkbhJzy2NJj6oSMDKklfI3X8jVf7bngMcCR3X3NcIo349I
Dt1r1GfwB+oWrhogZVnMFJKAoSYP8aQrLDVl7SQOAgTXz2IDD6bo1jga/8Kb72dD
h8D2qrkqWh7Hwdas3jqqbb9uiq6O2dJJY86FjffjXPo3jGlFjTsCAwEAAaOBrjCB
qzAdBgNVHQ4EFgQUVx+Aa0fM55v6NZR87Yi40QBa4J4wHwYDVR0jBBgwFoAUb+bF
bAe3bIsKgZKDXMtBHvaO0ScwRQYDVR0gAQH/BDswOTA3BgRVHSAAMC8wLQYIKwYB
BQUHAgEWIWh0dHA6Ly93d3cuc3QuY29tL1RQTS9yZXBvc2l0b3J5LzAOBgNVHQ8B
Af8EBAMCAAQwEgYDVR0TAQH/BAgwBgEB/wIBATANBgkqhkiG9w0BAQsFAAOCAQEA
4gllWq44PFWcv0JgMPOtyXDQx30YB5vBpjS0in7f/Y/r+1Dd8q3EZwNOwYApe+Lp
/ldNqCXw4XzmO8ZCVWOdQdVOqHZuSOhe++Jn0S7M4z2/1PQ6EbRczGfw3dlX63Ec
cEnrn6YMcgPC63Q+ID53vbTS3gpeX/SGpngtVwnzpuJ5rBajqSQUo5jBTBtuGQpO
Ko6Eu7U6Ouz7BVgOSn0mLbfSRb77PjOLZ3+97gSiMmV0iofS7ufemYqA8sF7ZFv/
lM2eOe/eeS56Jw+IPsnEU0Tf8Tn9hnEig1KP8VByRTWAJgiEOgX2nTs5iJbyZeIZ
RUjDHQQ5onqhgjpfRsC95g==
-----END CERTIFICATE-----""",
                  "NTC1": """-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIGAK3jXfbVMA0GCSqGSIb3DQEBBQUAMFIxUDAcBgNVBAMT
FU5UQyBUUE0gRUsgUm9vdCBDQSAwMTAlBgNVBAoTHk51dm90b24gVGVjaG5vbG9n
eSBDb3Jwb3JhdGlvbjAJBgNVBAYTAlRXMB4XDTEyMDcxMTE2MjkzMFoXDTMyMDcx
MTE2MjkzMFowUjFQMBwGA1UEAxMVTlRDIFRQTSBFSyBSb290IENBIDAxMCUGA1UE
ChMeTnV2b3RvbiBUZWNobm9sb2d5IENvcnBvcmF0aW9uMAkGA1UEBhMCVFcwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDoNqxhtD4yUtXhqKQGGZemoKJy
uj1RnWvmNgzItLeejNU8B6fOnpMQyoS4K72tMhhFRK2jV9RYzyJMSjEwyX0ASTO1
2yMti2UJQS60d36eGwk8WLgrFnnITlemshi01h9t1MOmay3TO1LLH/3/VDKJ+jbd
cbfIO2bBquN8r3/ojYUaNSPj6pK1mmsMoJXF4dGRSEwb/4ozBIw5dugm1MEq4Zj3
GZ0YPg5wyLRugQbt7DkUOX4FGuK5p/C0u5zX8u33EGTrDrRz3ye3zO+aAY1xXF/m
qwEqgxX5M8f0/DXTTO/CfeIksuPeOzujFtXfi5Cy64eeIZ0nAUG3jbtnGjoFAgMB
AAGjJjAkMA4GA1UdDwEB/wQEAwICBDASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqG
SIb3DQEBBQUAA4IBAQBBQznOPJAsD4Yvyt/hXtVJSgBX/+rRfoaqbdt3UMbUPJYi
pUoTUgaTx02DVRwommO+hLx7CS++1F2zorWC8qQyvNbg7iffQbbjWitt8NPE6kCr
q0Y5g7M/LkQDd5N3cFfC15uFJOtlj+A2DGzir8dlXU/0qNq9dBFbi+y+Y3rAT+wK
fktmN82UT861wTUzDvnXO+v7H5DYXjUU8kejPW6q+GgsccIbVTOdHNNWbMrcD9yf
oS91nMZ/+/n7IfFWXNN82qERsrvOFCDsbIzUOR30N0IP++oqGfwAbKFfCOCFUz6j
jpXUdJlh22tp12UMsreibmi5bsWYBgybwSbRgvzE
-----END CERTIFICATE-----""",
                  "NTC2": """-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIGAPadBmPZMA0GCSqGSIb3DQEBBQUAMFIxUDAcBgNVBAMT
FU5UQyBUUE0gRUsgUm9vdCBDQSAwMjAlBgNVBAoTHk51dm90b24gVGVjaG5vbG9n
eSBDb3Jwb3JhdGlvbjAJBgNVBAYTAlRXMB4XDTEyMDcxMTE2MzMyNFoXDTMyMDcx
MTE2MzMyNFowUjFQMBwGA1UEAxMVTlRDIFRQTSBFSyBSb290IENBIDAyMCUGA1UE
ChMeTnV2b3RvbiBUZWNobm9sb2d5IENvcnBvcmF0aW9uMAkGA1UEBhMCVFcwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDSagWxaANT1YA2YUSN7sq7yzOT
1ymbIM+WijhE5AGcLwLFoJ9fmaQrYL6fAW2EW/Q3yu97Q9Ysr8yYZ2XCCfxfseEr
Vs80an8Nk6LkTDz8+0Hm0Cct0klvNUAZEIvWpmgHZMvGijXyOcp4z494d8B28Ynb
I7x0JMXZZQQKQi+WfuHtntF+2osYScweocipPrGeONLKU9sngWZ2vnnvw1SBneTa
irxq0Q0SD6Bx9jtxvdf87euk8JzfPhX8jp8GEeAjmLwGR+tnOQrDmczGNmp7YYNN
R+Q7NZVoYWHw5jaoZnNxbouWUXZZxFqDsB/ndCKWtsIzRYPuWcqrFcmUN4SVAgMB
AAGjJjAkMA4GA1UdDwEB/wQEAwICBDASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqG
SIb3DQEBBQUAA4IBAQAIkdDSErzPLPYrVthw4lKjW4tRYelUicMPEHKjQeVUAAS5
y9XTzB4DWISDAFsgtQjqHJj0xCG+vpY0Rmn2FCO/0YpP+YBQkdbJOsiyXCdFy9e4
gGjQ24gw1B+rr84+pkI51y952NYBdoQDeb7diPe+24U94f//DYt/JQ8cJua4alr3
2Pohhh5TxCXXfU2EHt67KyqBSxCSy9m4OkCOGLHL2X5nQIdXVj178mw6DSAwyhwR
n3uJo5MvUEoQTFZJKGSXfab619mIgzEr+YHsIQToqf44VfDMDdM+MFiXQ3a5fLii
hEKQ9DhBPtpHAbhFA4jhCiG9HA8FdEplJ+M4uxNz
-----END CERTIFICATE-----""",
                  "IFX1": """-----BEGIN CERTIFICATE-----
MIIEnzCCA4egAwIBAgIEMV64bDANBgkqhkiG9w0BAQUFADBtMQswCQYDVQQGEwJE
RTEQMA4GA1UECBMHQmF2YXJpYTEhMB8GA1UEChMYSW5maW5lb24gVGVjaG5vbG9n
aWVzIEFHMQwwCgYDVQQLEwNBSU0xGzAZBgNVBAMTEklGWCBUUE0gRUsgUm9vdCBD
QTAeFw0wNTEwMjAxMzQ3NDNaFw0yNTEwMjAxMzQ3NDNaMHcxCzAJBgNVBAYTAkRF
MQ8wDQYDVQQIEwZTYXhvbnkxITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2ll
cyBBRzEMMAoGA1UECxMDQUlNMSYwJAYDVQQDEx1JRlggVFBNIEVLIEludGVybWVk
aWF0ZSBDQSAwMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALftPhYN
t4rE+JnU/XOPICbOBLvfo6iA7nuq7zf4DzsAWBdsZEdFJQfaK331ihG3IpQnlQ2i
YtDim289265f0J4OkPFpKeFU27CsfozVaNUm6UR/uzwA8ncxFc3iZLRMRNLru/Al
VG053ULVDQMVx2iwwbBSAYO9pGiGbk1iMmuZaSErMdb9v0KRUyZM7yABiyDlM3cz
UQX5vLWV0uWqxdGoHwNva5u3ynP9UxPTZWHZOHE6+14rMzpobs6Ww2RR8BgF96rh
4rRAZEl8BXhwiQq4STvUXkfvdpWH4lzsGcDDtrB6Nt3KvVNvsKz+b07Dk+Xzt+EH
NTf3Byk2HlvX+scCAwEAAaOCATswggE3MB0GA1UdDgQWBBQ4k8292HPEIzMV4bE7
qWoNI8wQxzAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBADBYBgNV
HSABAf8ETjBMMEoGC2CGSAGG+EUBBy8BMDswOQYIKwYBBQUHAgEWLWh0dHA6Ly93
d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvaW5kZXguaHRtbDCBlwYDVR0jBIGP
MIGMgBRW65FEhWPWcrOu1EWWC/eUDlRCpqFxpG8wbTELMAkGA1UEBhMCREUxEDAO
BgNVBAgTB0JhdmFyaWExITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2llcyBB
RzEMMAoGA1UECxMDQUlNMRswGQYDVQQDExJJRlggVFBNIEVLIFJvb3QgQ0GCAQMw
DQYJKoZIhvcNAQEFBQADggEBABJ1+Ap3rNlxZ0FW0aIgdzktbNHlvXWNxFdYIBbM
OKjmbOos0Y4O60eKPu259XmMItCUmtbzF3oKYXq6ybARUT2Lm+JsseMF5VgikSlU
BJALqpKVjwAds81OtmnIQe2LSu4xcTSavpsL4f52cUAu/maMhtSgN9mq5roYptq9
DnSSDZrX4uYiMPl//rBaNDBflhJ727j8xo9CCohF3yQUoQm7coUgbRMzyO64yMIO
3fhb+Vuc7sNwrMOz3VJN14C3JMoGgXy0c57IP/kD5zGRvljKEvrRC2I147+fPeLS
DueRMS6lblvRKiZgmGAg7YaKOkOaEmVDMQ+fTo2Po7hI5wc=
-----END CERTIFICATE-----""",
                  "IFX2": """-----BEGIN CERTIFICATE-----
MIIEnzCCA4egAwIBAgIEaItIgTANBgkqhkiG9w0BAQUFADBtMQswCQYDVQQGEwJE
RTEQMA4GA1UECBMHQmF2YXJpYTEhMB8GA1UEChMYSW5maW5lb24gVGVjaG5vbG9n
aWVzIEFHMQwwCgYDVQQLEwNBSU0xGzAZBgNVBAMTEklGWCBUUE0gRUsgUm9vdCBD
QTAeFw0wNjEyMjExMDM0MDBaFw0yNjEyMjExMDM0MDBaMHcxCzAJBgNVBAYTAkRF
MQ8wDQYDVQQIEwZTYXhvbnkxITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2ll
cyBBRzEMMAoGA1UECxMDQUlNMSYwJAYDVQQDEx1JRlggVFBNIEVLIEludGVybWVk
aWF0ZSBDQSAwMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK6KnP5R
8ppq9TtPu3mAs3AFxdWhzK5ks+BixGR6mpzyXG64Bjl4xzBXeBIVtlBZXYvIAJ5s
eCTEEsnZc9eKNJeFLdmXQ/siRrTeonyxoS4aL1mVEQebLUz2gN9J6j1ewly+OvGk
jEYouGCzA+fARzLeRIrhuhBI0kUChbH7VM8FngJsbT4xKB3EJ6Wttma25VSimkAr
SPS6dzUDRS1OFCWtAtHJW6YjBnA4wgR8WfpXsnjeNpwEEB+JciWu1VAueLNI+Kis
RiferCfsgWRvHkR6RQf04h+FlhnYHJnf1ktqcEi1oYAjLsbYOAwqyoU1Pev9cS28
EA6FTJcxjuHhH9ECAwEAAaOCATswggE3MB0GA1UdDgQWBBRDMlr1UAQGVIkwzamm
fceAZ7l4ATAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBADBYBgNV
HSABAf8ETjBMMEoGC2CGSAGG+EUBBy8BMDswOQYIKwYBBQUHAgEWLWh0dHA6Ly93
d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvaW5kZXguaHRtbDCBlwYDVR0jBIGP
MIGMgBRW65FEhWPWcrOu1EWWC/eUDlRCpqFxpG8wbTELMAkGA1UEBhMCREUxEDAO
BgNVBAgTB0JhdmFyaWExITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2llcyBB
RzEMMAoGA1UECxMDQUlNMRswGQYDVQQDExJJRlggVFBNIEVLIFJvb3QgQ0GCAQMw
DQYJKoZIhvcNAQEFBQADggEBAIZAaYGzf9AYv6DqoUNx6wdpayhCeX75/IHuFQ/d
gLzat9Vd6qNKdAByskpOjpE0KRauEzD/BhTtkEJDazPSmVP1QxAPjqGaD+JjqhS/
Q6aY+1PSDi2zRIDA66V2yFJDcUBTtShbdTg144YSkVSY5UCKhQrsdg8yAbs7saAB
LHzVebTXffjmkTk5GZk26d/AZQRjfssta1N/TWhWTfuZtwYvjZmgDPeCfr6AOPLr
pVJz+ntzUKGpQ+5mwDJXMZ0qeiFIgXUlU0D+lfuajc/x9rgix9cM+o7amgDlRi1T
55Uu2vzUQ9jLUaISFaTTMag+quBDhx8BDVu+igLp5hvBtxQ=
-----END CERTIFICATE-----""",
                  "IFX3": """-----BEGIN CERTIFICATE-----
MIIEnzCCA4egAwIBAgIEH7fYljANBgkqhkiG9w0BAQUFADBtMQswCQYDVQQGEwJE
RTEQMA4GA1UECBMHQmF2YXJpYTEhMB8GA1UEChMYSW5maW5lb24gVGVjaG5vbG9n
aWVzIEFHMQwwCgYDVQQLEwNBSU0xGzAZBgNVBAMTEklGWCBUUE0gRUsgUm9vdCBD
QTAeFw0wNzA0MTMxNjQ0MjRaFw0yNzA0MTMxNjQ0MjRaMHcxCzAJBgNVBAYTAkRF
MQ8wDQYDVQQIEwZTYXhvbnkxITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2ll
cyBBRzEMMAoGA1UECxMDQUlNMSYwJAYDVQQDEx1JRlggVFBNIEVLIEludGVybWVk
aWF0ZSBDQSAwMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJWdPAuH
z/p1tIwB1QXlPD/PjedZ4uBZdwPH5tI3Uve0TzbR/mO5clx/loWn7nZ5cHkH1nhB
R67JEFY0a9GithPfITh0XRxPcisLBE/SoqZ90KHFaS+N6SwOpdCP0GlUg1OesKCF
79Z6fXrkTZsVpPqdawdZK+oUsDO9z9U6xqV7bwsS75Y+QiHsm6UTgAkSNQnuFMP3
NqQyDi/BaWaYRGQ6K8pM7Y7e1h21z/+5X7LncZXU8hgpYpu2zQPg96IkYboVUKL4
00snaPcOvfagsBUGlBltNfz7geaSuWTCdwEiwlkCYZqCtbkAj5FiStajrzP72BfT
2fshIv+5eF7Qp5ECAwEAAaOCATswggE3MB0GA1UdDgQWBBTGyypNtylL6RFyT1BB
MQtMQvibsjAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBADBYBgNV
HSABAf8ETjBMMEoGC2CGSAGG+EUBBy8BMDswOQYIKwYBBQUHAgEWLWh0dHA6Ly93
d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvaW5kZXguaHRtbDCBlwYDVR0jBIGP
MIGMgBRW65FEhWPWcrOu1EWWC/eUDlRCpqFxpG8wbTELMAkGA1UEBhMCREUxEDAO
BgNVBAgTB0JhdmFyaWExITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2llcyBB
RzEMMAoGA1UECxMDQUlNMRswGQYDVQQDExJJRlggVFBNIEVLIFJvb3QgQ0GCAQMw
DQYJKoZIhvcNAQEFBQADggEBAGN1bkh4J90DGcOPP2BlwE6ejJ0iDKf1zF+7CLu5
WS5K4dvuzsWUoQ5eplUt1LrIlorLr46mLokZD0RTG8t49Rcw4AvxMgWk7oYk69q2
0MGwXwgZ5OQypHaPwslmddLcX+RyEvjrdGpQx3E/87ZrQP8OKnmqI3pBlB8QwCGL
SV9AERaGDpzIHoObLlUjgHuD6aFekPfeIu1xbN25oZCWmqFVIhkKxWE1Xu+qqHIA
dnCFhoIWH3ie9OsJh/iDRaANYYGyplIibDx1FJA8fqiBiBBKUlPoJvbqmZs4meMd
OoeOuCvQ7op28UtaoV6H6BSYmN5dOgW7r1lX2Re0nd84NGE=
-----END CERTIFICATE-----""",
                  "IFX4": """-----BEGIN CERTIFICATE-----
MIIEnzCCA4egAwIBAgIEDhD4wDANBgkqhkiG9w0BAQUFADBtMQswCQYDVQQGEwJE
RTEQMA4GA1UECBMHQmF2YXJpYTEhMB8GA1UEChMYSW5maW5lb24gVGVjaG5vbG9n
aWVzIEFHMQwwCgYDVQQLEwNBSU0xGzAZBgNVBAMTEklGWCBUUE0gRUsgUm9vdCBD
QTAeFw0wNzEyMDMxMzA3NTVaFw0yNzEyMDMxMzA3NTVaMHcxCzAJBgNVBAYTAkRF
MQ8wDQYDVQQIEwZTYXhvbnkxITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2ll
cyBBRzEMMAoGA1UECxMDQUlNMSYwJAYDVQQDEx1JRlggVFBNIEVLIEludGVybWVk
aWF0ZSBDQSAwNDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN3UBmDk
jJzzJ+WCgrq4tILtE9KJPMGHwvCsbJOlo7eHiEb8JQzGK1prkPQ3dowFRXPnqONP
WUa36/J3R32xgvuZHqAdliZCt8IUb9qYhDenuXo1SSqJ8LWp30QIJ0vnkaQ2TCkO
bveZZR3hK2OZKRTkFaV/iy2RH+Qs4JAe3diD8mlIu2gXAXnKJSkrzW6gbMzrlTOi
RCuGcatpy7Hfmodbz/0Trbuwtc3dyJZ3Ko1z9bz2Oirjh93RrmYjbtL0HhkAjMOR
83GLrzwUddSqmxtXXX8j5i+/gmE3AO71swOIESdGugxaKUzJ1jTqWKMZcx0E6BFI
lDIfKk0fJlSxHfECAwEAAaOCATswggE3MB0GA1UdDgQWBBSIs8E/YQXRBCKfWsDr
SZVkrNRzvTAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBADBYBgNV
HSABAf8ETjBMMEoGC2CGSAGG+EUBBy8BMDswOQYIKwYBBQUHAgEWLWh0dHA6Ly93
d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvaW5kZXguaHRtbDCBlwYDVR0jBIGP
MIGMgBRW65FEhWPWcrOu1EWWC/eUDlRCpqFxpG8wbTELMAkGA1UEBhMCREUxEDAO
BgNVBAgTB0JhdmFyaWExITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2llcyBB
RzEMMAoGA1UECxMDQUlNMRswGQYDVQQDExJJRlggVFBNIEVLIFJvb3QgQ0GCAQMw
DQYJKoZIhvcNAQEFBQADggEBAFtqClQNBLOzcGZUpsBqlz3frzM45iiBpxosG1Re
IgoAgtIBEtl609TG51tmpm294KqpfKZVO+xNzovm8k/heGb0jmYf+q1ggrk2qT4v
Qy2jgE0jbP/P8WWq8NHC13uMcBUGPaka7yofEDDwz7TcduQyJVfG2pd1vflnzP0+
iiJpfCk3CAQQnb+B7zsOp7jHNwpvHP+FhNwZaikaa0OdR/ML9da1sOOW3oJSTEjW
SMLuhaZHtcVgitvtOVvCI/aq47rNJku3xQ7c/s8FHnFzQQ+Q4TExbP20SrqQIlL/
9sFAb7/nKYNauusakiF3pfvMrJOJigNfJyIcWaGfyyQtVVI=
-----END CERTIFICATE-----""",
                  "IFX5": """-----BEGIN CERTIFICATE-----
MIIEnzCCA4egAwIBAgIEVuRoqzANBgkqhkiG9w0BAQUFADBtMQswCQYDVQQGEwJE
RTEQMA4GA1UECBMHQmF2YXJpYTEhMB8GA1UEChMYSW5maW5lb24gVGVjaG5vbG9n
aWVzIEFHMQwwCgYDVQQLEwNBSU0xGzAZBgNVBAMTEklGWCBUUE0gRUsgUm9vdCBD
QTAeFw0wOTEyMTExMDM4NDJaFw0yOTEyMTExMDM4NDJaMHcxCzAJBgNVBAYTAkRF
MQ8wDQYDVQQIEwZTYXhvbnkxITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2ll
cyBBRzEMMAoGA1UECxMDQUlNMSYwJAYDVQQDEx1JRlggVFBNIEVLIEludGVybWVk
aWF0ZSBDQSAwNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL79zMCO
bjkg7gCWEuyGO49CisF/QrGoz9adW1FBuSW8U9IOlvWXNsvoasC1mhrsfkRRojuU
mWifxxxcVfOI9v1SbRfJ+i6lG21IcVe6ywLJdDliT+3vzvrb/2hU/XjCCMDWb/Pw
aZslV5iL4QEiKxvRIiWMYHW0MkkL7mzRBDVN/Vz3ZiL5Lpq7awiKuX9OXpS2a1wf
qSGAlm2TxjU884q9Ky85JJugn0Q/C3dc8aaFPKLHlRs6rIvN1l0LwB1b5EWPzTPJ
d9EhRPFJOAbJS66nSgX06Fl7eWB71ow6w/25otLQCbpy6OrF8wBVMtPMHqFb1c32
PaaNzpCBnIU7vaMCAwEAAaOCATswggE3MB0GA1UdDgQWBBS7z3zBhCExZtq1vlOo
cBTd00jYzDAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBADBYBgNV
HSABAf8ETjBMMEoGC2CGSAGG+EUBBy8BMDswOQYIKwYBBQUHAgEWLWh0dHA6Ly93
d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvaW5kZXguaHRtbDCBlwYDVR0jBIGP
MIGMgBRW65FEhWPWcrOu1EWWC/eUDlRCpqFxpG8wbTELMAkGA1UEBhMCREUxEDAO
BgNVBAgTB0JhdmFyaWExITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2llcyBB
RzEMMAoGA1UECxMDQUlNMRswGQYDVQQDExJJRlggVFBNIEVLIFJvb3QgQ0GCAQMw
DQYJKoZIhvcNAQEFBQADggEBAHomNJtmFNtRJI2+s6ZwdzCTHXXIcR/T+N/lfPbE
hIUG4Kg+3uQMP7zBi22m3I3Kk9SXsjLqV5mnsQUGMGlF7jw5W5Q+d6NSJz4taw9D
2DsiUxE/i5vrjWiUaWxv2Eckd4MUexe5Qz8YSh4FPqLB8FZnAlgx2kfdzRIUjkMq
EgFK8ZRSUjXdczvsud68YPVMIZTxK0L8POGJ6RYiDrjTelprfZ4pKKZ79XwxwAIo
pG6emUEf+doRT0KoHoCHr9vvWCWKhojqlQ6jflPZcEsNBMbq5KHVN77vOU58OKx1
56v3EaqrZenVFt8+n6h2NzhOmg2quQXIr0V9jEg8GAMehDs=
-----END CERTIFICATE-----""",
                  "IFX8": """-----BEGIN CERTIFICATE-----
MIIEnzCCA4egAwIBAgIEfGoY6jANBgkqhkiG9w0BAQUFADBtMQswCQYDVQQGEwJE
RTEQMA4GA1UECBMHQmF2YXJpYTEhMB8GA1UEChMYSW5maW5lb24gVGVjaG5vbG9n
aWVzIEFHMQwwCgYDVQQLEwNBSU0xGzAZBgNVBAMTEklGWCBUUE0gRUsgUm9vdCBD
QTAeFw0xMjA3MTcwOTI0NTJaFw0zMDEwMTgyMzU5NTlaMHcxCzAJBgNVBAYTAkRF
MQ8wDQYDVQQIEwZTYXhvbnkxITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2ll
cyBBRzEMMAoGA1UECxMDQUlNMSYwJAYDVQQDEx1JRlggVFBNIEVLIEludGVybWVk
aWF0ZSBDQSAwODCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOJaIJu6
r/betrMgWJ/JZ5j8ytoAA9RWq0cw7+W0e5L2kDLJMM288wYT+iEbfwx6sWSLAl7q
okXYDtTB9MFNhQ5ZWFLslFXbYigtXJxwANcSdPISTF1Czn6LLi1fu1EHddwCXFC8
xaX0iGgQ9pZklvAy2ijK9BPHquWisisEiWZNRT9dCVylzOR3+p2YOC3ZrRmg7Bj+
DkC7dltTTO6dPR+LNOFe01pJlpZdF4YHcu4EC10gRu0quZz1LtDZWFKezK7rg5Rj
LSAJbKOsGXjl6hQXMtADEX9Vlz1vItD21OYCNRsu6VdipiL0bl0aAio4BV3GMyjk
0gHnQwCk9k/YPU8CAwEAAaOCATswggE3MB0GA1UdDgQWBBRMS01kiQjkW/5aENNj
h6aIrsHPeDAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBADBYBgNV
HSABAf8ETjBMMEoGC2CGSAGG+EUBBy8BMDswOQYIKwYBBQUHAgEWLWh0dHA6Ly93
d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvaW5kZXguaHRtbDCBlwYDVR0jBIGP
MIGMgBRW65FEhWPWcrOu1EWWC/eUDlRCpqFxpG8wbTELMAkGA1UEBhMCREUxEDAO
BgNVBAgTB0JhdmFyaWExITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2llcyBB
RzEMMAoGA1UECxMDQUlNMRswGQYDVQQDExJJRlggVFBNIEVLIFJvb3QgQ0GCAQMw
DQYJKoZIhvcNAQEFBQADggEBALMiDyQ9WKH/eTI84Mk8KYk+TXXEwf+fhgeCvxOQ
G0FTSmOpJaNIzxWXr/gDbY3dO0ODjWRKYvhimZUuV+ckMA+wZX2C6o8g5njpWIOH
pSAa+W35ijArh0Zt3MASJ46avd+fnQGTdzT0hK46gx6n2KixLvaZsR3JtuwUFYlQ
wzmz/UsbBNEoPiR8p5E0Zf5GEGiTqkmBVYyS6XA34axpMMRHy0wI7AGs0gVihwUM
rr0iWOu+GAcrm11lcYzqJvuEkfenAF62ufA2Ktv+Ut2xiRC0jUIp73CeplAJsqBr
camV3pJn3qYPI5c1njMRYnoRFWQbrOR5ADWDQLFQPYRrJmg=
-----END CERTIFICATE-----""",
                  "IFX15": """-----BEGIN CERTIFICATE-----
MIIEnzCCA4egAwIBAgIER3V5aDANBgkqhkiG9w0BAQUFADBtMQswCQYDVQQGEwJE
RTEQMA4GA1UECBMHQmF2YXJpYTEhMB8GA1UEChMYSW5maW5lb24gVGVjaG5vbG9n
aWVzIEFHMQwwCgYDVQQLEwNBSU0xGzAZBgNVBAMTEklGWCBUUE0gRUsgUm9vdCBD
QTAeFw0xMjExMTQxNDQzMzRaFw0zMDEwMTgyMzU5NTlaMHcxCzAJBgNVBAYTAkRF
MQ8wDQYDVQQIEwZTYXhvbnkxITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2ll
cyBBRzEMMAoGA1UECxMDQUlNMSYwJAYDVQQDEx1JRlggVFBNIEVLIEludGVybWVk
aWF0ZSBDQSAxNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKS6pgcg
OQWSozVbMkdf9jZkpGdT4U735zs0skfpjoKK2CgpLMO/+oGKbObm/DQPRQO/oxvq
jJNBKz55QBgKd+MoQ6t+2J8mcQ91Nfwqnm1C4r+c4zezJ1Utk/KIYNqpFDAzefBA
/lK8IxQ6kmzxcIFE4skaFsSgkearSZGG6sA9A51yxwvs8yUrQF51ICEUM7wDb4cM
53utaFdm6p6m9UZGSmmrdTiemOkuuwtl8IUQXfuk9lFyQsACBTM95Hrts0IzI6hX
QeTwSL4JqyEnKP9vbtT4eXzWNycqSYBf0+Uo/HHZo9WuVDUaA4I9zcmD0qCvSOT0
NAj4ifJ7SPGInU0CAwEAAaOCATswggE3MB0GA1UdDgQWBBR4pAnEV95pJvbfQsYR
TrflaptW5zAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBADBYBgNV
HSABAf8ETjBMMEoGC2CGSAGG+EUBBy8BMDswOQYIKwYBBQUHAgEWLWh0dHA6Ly93
d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvaW5kZXguaHRtbDCBlwYDVR0jBIGP
MIGMgBRW65FEhWPWcrOu1EWWC/eUDlRCpqFxpG8wbTELMAkGA1UEBhMCREUxEDAO
BgNVBAgTB0JhdmFyaWExITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2llcyBB
RzEMMAoGA1UECxMDQUlNMRswGQYDVQQDExJJRlggVFBNIEVLIFJvb3QgQ0GCAQMw
DQYJKoZIhvcNAQEFBQADggEBAAnZDdJZs5QgAXnl0Jo5sCqktZcwcK+V1+uhsqrT
Z7OJ9Ze1YJ9XB14KxRfmck7Erl5HVc6PtUcLnR0tuJKKKqm7dTe4sQEFYd5usjrW
KSG6y7BOH7AdonocILY9OIxuNwxMAqhK8LIjkkRCeOWSvCqLnaLtrP52C0fBkTTM
SWX7YnsutXEpwhro3Qsnm9hL9s3s/WoIuNKUcLFH/qWKztpxXnF0zip73gcZbwEy
1GPQQpYnxFJ2R2ab2RHlO+3Uf3FDxn+eRLXNl95ZZ6GE4OIIpKEg2urIiig0HmGA
ijO6JfJxT30H9QNsx78sjYs7pOfMw6DfiqJ8Fx82GcCUOyM=
-----END CERTIFICATE-----""" }


def integer_ceil(a, b):
    """Return the ceil integer of a div b."""
    quanta, mod = divmod(a, b)
    if mod:
        quanta += 1
    return quanta


def i2osp(x, x_len):
    """
    Converts the integer x to its big-endian representation of length
    x_len.
    """
    if x > 256**x_len:
        raise exceptions.IntegerTooLarge
    h = hex(x)[2:]
    if h[-1] == 'L':
        h = h[:-1]
    if len(h) & 1 == 1:
        h = '0%s' % h
    x = h.decode('hex')
    return '\x00' * int(x_len-len(x)) + x


def mgf1(mgf_seed, mask_len, hash_class=hashlib.sha1):
    """
    Mask Generation Function v1 from the PKCS#1 v2.0 standard.

    :param mgs_seed: the seed, a byte string
    :param mask_len: the length of the mask to generate
    :param hash_class: the digest algorithm to use, default is SHA1

    :returns:: a pseudo-random mask, as a byte string
    """
    h_len = hash_class().digest_size
    if mask_len > 0x10000:
        raise ValueError('mask too long')
    T = ''
    for i in xrange(0, integer_ceil(mask_len, h_len)):
        C = i2osp(i, 4)
        T = T + hash_class(mgf_seed + C).digest()
    return bytearray(T[:mask_len])


def tpm_oaep(plaintext, keylen):
    """Pad plaintext with the TPM-specific varient of OAEP

    :param plaintext: The data that requires padding
    :param keylen: The length of the encryption key
    :returns: a padded plaintext
    """
    m = hashlib.sha1()
    m.update('TCPA')

    seed = os.urandom(20)
    seedstart = 1
    seedend = seedstart + m.digest_size

    output = bytearray(keylen)
    output[0] = 0
    output[seedstart:seedend] = seed

    shastart = 21
    shaend = 21 + m.digest_size
    output[shastart:shaend] = m.digest()

    output[-(len(plaintext)+1)] = 1
    offset = keylen - len(plaintext)
    output[offset:keylen] = plaintext

    dbmask = mgf1(seed, keylen - m.digest_size - 1)
    for i in range(shastart, keylen):
        output[i] ^= dbmask[i - shastart]

    seedmask = mgf1(output[seedend:keylen], m.digest_size)
    for i in range(seedstart, seedend):
        output[i] ^= seedmask[i-1]

    return output

def get_ek(context):
    """Retrieve the raw Endorsement Key from the TPM.

    :param context: The TSS context to use
    :returns: a TspiObject representing the Endorsement Key
    """
    tpm = context.get_tpm_object()
    try:
        return tpm.get_pub_endorsement_key()
    except tspi_exceptions.TSS_E_POLICY_NO_SECRET:
        policy = context.create_policy(TSS_POLICY_USAGE)
        policy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)
        policy.assign(tpm)
        return tpm.get_pub_endorsement_key()

def get_ekcert(context):
    """Retrieve the Endoresement Key's certificate from the TPM.

    :param context: The TSS context to use
    :returns: a bytearray containing the x509 certificate
    """
    nvIndex = TSS_NV_DEFINED | TPM_NV_INDEX_EKCert

    nv = context.create_nv(0)
    nv.set_index(nvIndex)

    # Try reading without authentication, and then fall back to using the
    # well known secret
    try:
        blob = nv.read_value(0, 5)
    except tspi_exceptions.TPM_E_AUTH_CONFLICT:
        policy = context.create_policy(TSS_POLICY_USAGE)
        policy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)
        policy.assign(nv)
        blob = nv.read_value(0, 5)

    # Verify that the certificate is well formed
    tag = blob[0] << 8 | blob[1]
    if tag != 0x1001:
            print "Invalid tag %x %x\n" % (blob[0], blob[1])
            return None

    certtype = blob[2]
    if certtype != 0:
            print "Not a full certificate\n"
            return None

    ekbuflen = blob[3] << 8 | blob[4]
    offset = 5

    blob = nv.read_value(offset, 2)
    if len(blob) < 2:
        print "Invalid length"
        return None

    tag = blob[0] << 8 | blob[1]
    if tag == 0x1002:
        offset += 2
        ekbuflen -= 2
    elif blob[0] != 0x30:
        print "Invalid header %x %x" % (blob[0], blob[1])
        return None
    
    ekbuf = bytearray()
    ekoffset = 0

    while ekoffset < ekbuflen:
        length = ekbuflen-ekoffset
        if length > 128:
            length = 128
        blob = nv.read_value(offset, length)
        ekbuf += blob
        offset += len(blob)
        ekoffset += len(blob)

    return ekbuf


def create_aik(context):
    """Ask the TPM to create an Authorisation Identity Key

    :param context: The TSS context to use
    :returns: a tuple containing the RSA public key and a TSS key blob
    """

    n = bytearray([0xff] * (2048/8))

    srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)

    keypolicy = srk.get_policy_object(TSS_POLICY_USAGE)
    keypolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    tpm = context.get_tpm_object()
    tpmpolicy = context.create_policy(TSS_POLICY_USAGE)
    tpmpolicy.assign(tpm)
    tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    pcakey = context.create_rsa_key(TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048)
    pcakey.set_modulus(n)

    aik = context.create_rsa_key(TSS_KEY_TYPE_IDENTITY|TSS_KEY_SIZE_2048)

    data = tpm.collate_identity_request(srk, pcakey, aik)

    pubkey = aik.get_pubkeyblob()
    blob = aik.get_keyblob()

    return (pubkey, blob)


def verify_ek(context, ekcert):
    """Verify that the provided EK certificate is signed by a trusted root

    :param context: The TSS context to use
    :param ekcert: The Endorsement Key certificate
    :returns: True if the certificate can be verified, false otherwise
    """
    verified = False
    ek509 = M2Crypto.X509.load_cert_der_string(ekcert)
    for signer in trusted_certs:
        signcert = M2Crypto.X509.load_cert_string(trusted_certs[signer])
        signkey = signcert.get_pubkey()
        if ek509.verify(signkey) == 1:
            verified = True

    return verified


def generate_challenge(context, ekcert, aikpub, secret, ek=None):
    """ Generate a challenge to verify that the AIK is under the control of
    the TPM we're talking to.

    :param context: The TSS context to use
    :param ekcert: The Endorsement Key certificate
    :param aikpub: The public Attestation Identity Key blob
    :param secret: The secret to challenge the TPM with
    :param ek: TspiKey representing ek. ekcert is ignored if ek is provided.

    :returns: a tuple containing the asymmetric and symmetric components of
    the challenge
    """

    aeskey = bytearray(os.urandom(16))
    iv = bytearray(os.urandom(16))

    if ek is None:
        # Replace rsaesOaep OID with rsaEncryption
        ekcert = ekcert.replace('\x2a\x86\x48\x86\xf7\x0d\x01\x01\x07',
                                '\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01')

        x509 = M2Crypto.X509.load_cert_string(ekcert, M2Crypto.X509.FORMAT_DER)
        pubkey = x509.get_pubkey()
        rsakey = pubkey.get_rsa()
    else:
        pubkey = ek.get_pubkey()
        n = m2.bin_to_bn(pubkey)
        n = m2.bn_to_mpi(n)
        e = m2.hex_to_bn("010001")
        e = m2.bn_to_mpi(e)
        rsakey = M2Crypto.RSA.new_pub_key((e, n))

    # TPM_ALG_AES, TPM_ES_SYM_CBC_PKCS5PAD, key length
    asymplain = bytearray([0x00, 0x00, 0x00, 0x06, 0x00, 0xff, 0x00, 0x10])
    asymplain += aeskey

    m = hashlib.sha1()
    m.update(aikpub)
    asymplain += m.digest()

    # Pad with the TCG varient of OAEP
    asymplain = tpm_oaep(asymplain, len(rsakey)/8)

    # Generate the EKpub-encrypted asymmetric buffer containing the aes key
    asymenc = bytearray(rsakey.public_encrypt(asymplain,
                                              M2Crypto.RSA.no_padding))

    # And symmetrically encrypt the secret with AES
    cipher = M2Crypto.EVP.Cipher('aes_128_cbc', aeskey, iv, 1)
    cipher.update(secret)
    symenc = cipher.final()

    symheader = struct.pack('!llhhllll', len(symenc) + len(iv),
                            TPM_ALG_AES, TPM_ES_SYM_CBC_PKCS5PAD,
                            TPM_SS_NONE, 12, 128, len(iv), 0)

    symenc = symheader + iv + symenc

    return (asymenc, symenc)


def aik_challenge_response(context, aikblob, asymchallenge, symchallenge):
    """Ask the TPM to respond to a challenge

    :param context: The TSS context to use
    :param aikblob: The Attestation Identity Key blob
    :param asymchallenge: The asymmetrically encrypted challenge
    :param symchallenge: The symmertrically encrypted challenge    
    :returns: The decrypted challenge
    """

    srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)
    srkpolicy = srk.get_policy_object(TSS_POLICY_USAGE)
    srkpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    tpm = context.get_tpm_object()
    tpmpolicy = context.create_policy(TSS_POLICY_USAGE)
    tpmpolicy.assign(tpm)
    tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    aik = context.load_key_by_blob(srk, aikblob)

    try:
        return tpm.activate_identity(aik, asymchallenge, symchallenge)
    except tspi_exceptions.TPM_E_DECRYPT_ERROR:
        return None


def quote_verify(data, validation, aik, pcrvalues):
    """Verify that a generated quote came from a trusted TPM and matches the
    previously obtained PCR values

    :param data: The TPM_QUOTE_INFO structure provided by the TPM
    :param validation: The validation information provided by the TPM
    :param aik: The object representing the Attestation Identity Key
    :param pcrvalues: A dictionary containing the PCRs read from the TPM
    :returns: True if the quote can be verified, False otherwise
    """
    select = 0
    maxpcr = 0

    # Verify that the validation blob was generated by a trusted TPM
    pubkey = aik.get_pubkey()

    n = m2.bin_to_bn(pubkey)
    n = m2.bn_to_mpi(n)
    e = m2.hex_to_bn("010001")
    e = m2.bn_to_mpi(e)
    rsa = M2Crypto.RSA.new_pub_key((e, n))

    m = hashlib.sha1()
    m.update(data)
    md = m.digest()

    try:
        ret = rsa.verify(md, str(validation), algo='sha1')
    except M2Crypto.RSA.RSAError:
        return False

    # And then verify that the validation blob corresponds to the PCR
    # values we have
    values = bytearray()

    for pcr in sorted(pcrvalues):
        values += pcrvalues[pcr]
        select |= (1 << pcr)
        maxpcr = pcr

    if maxpcr < 16:
        header = struct.pack('!H', 2)
        header += struct.pack('@H', select)
        header += struct.pack('!I', len(values))
    else:
        header = struct.pack('!H', 4)
        header += struct.pack('@I', select)
        header += struct.pack('!I', len(values))

    pcr_blob = header + values

    m = hashlib.sha1()
    m.update(pcr_blob)
    pcr_hash = m.digest()

    if pcr_hash == data[8:28]:
        return True
    else:
        return False


def take_ownership(context):
    """Take ownership of a TPM

    :param context: The TSS context to use

    :returns: True on ownership being taken, False if the TPM is already owned
    """

    tpm = context.get_tpm_object()
    tpmpolicy = tpm.get_policy_object(TSS_POLICY_USAGE)
    tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    srk = context.create_rsa_key(TSS_KEY_TSP_SRK | TSS_KEY_AUTHORIZATION)
    srkpolicy = srk.get_policy_object(TSS_POLICY_USAGE)
    srkpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    try:
        tpm.take_ownership(srk)
    except tspi_exceptions.TPM_E_DISABLED_CMD:
        return False

    return True
