---
description: CVE-2019-6486, HIGH, Go before 1.10.8 and 1.11.x before 1.11.5 mishandles P-521 and P-384 elliptic curves, which allows attackers to cause a denial of service (CPU consumption) or possibly conduct ECDH private key recovery attacks.
title: Go before 1.10.8 and 1.11.x before 1.11.5 mishandles P-521 and P-384 elliptic curves, which allows attackers to cause a denial of service (CPU consumption) or possibly conduct ECDH private key recovery attacks.
date_published: "2022-11-22"
last_updated: "2022-11-22"
xray_id: XRAY-75663
vul_id: CVE-2019-6486
cvss: 8.2
severity: high
discovered_by: 
type: vulnerability

---

## Summary

Go before 1.10.8 and 1.11.x before 1.11.5 mishandles P-521 and P-384 elliptic curves, which allows attackers to cause a denial of service (CPU consumption) or possibly conduct ECDH private key recovery attacks.

## Component

github.com/golang/go/src/crypto/elliptic
github.com/golang/go

## Affected versions

(,1.10.8)
[1.11.0,1.11.5)
(,1.10.8)
[1.11.0,1.11.5)

## Description

Go before 1.10.8 and 1.11.x before 1.11.5 mishandles P-521 and P-384 elliptic curves, which allows attackers to cause a denial of service (CPU consumption) or possibly conduct ECDH private key recovery attacks.

## PoC



## Vulnerability Mitigations

No mitigations are supplied for this issue

## References

[http://www.securityfocus.com/bid/106740](http://www.securityfocus.com/bid/106740)
[https://github.com/golang/go/commit/42b42f71cf8f5956c09e66230293dfb5db652360](https://github.com/golang/go/commit/42b42f71cf8f5956c09e66230293dfb5db652360)
[https://github.com/golang/go/issues/29903](https://github.com/golang/go/issues/29903)
[https://groups.google.com/forum/#!topic/golang-announce/mVeX35iXuSw](https://groups.google.com/forum/#!topic/golang-announce/mVeX35iXuSw)
[https://www.debian.org/security/2019/dsa-4379](https://www.debian.org/security/2019/dsa-4379)
[https://www.debian.org/security/2019/dsa-4380](https://www.debian.org/security/2019/dsa-4380)
[https://github.com/google/wycheproof](https://github.com/google/wycheproof)
[https://lists.debian.org/debian-lts-announce/2019/02/msg00009.html](https://lists.debian.org/debian-lts-announce/2019/02/msg00009.html)
[http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00042.html](http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00042.html)
[http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00060.html](http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00060.html)
[http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00011.html](http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00011.html)
[http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00015.html](http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00015.html)

