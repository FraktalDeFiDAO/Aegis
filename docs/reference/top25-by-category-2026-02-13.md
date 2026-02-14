# Top 25 Vulnerabilities By Category (2026-02-13)

This document tracks a normalized Top 25 list for each security category used in this repo.

## Scope

Categories included:

- Web
- Desktop
- Mobile
- Web3
- API

Machine-readable source of truth:

- `docs/reference/data/top25-by-category-2026-02-13.json`

## Methodology

Some standards publish official Top 10 lists, not Top 25.
To keep exactly 25 items per category, this dataset preserves official ordering for each Top 10 and extends to 25 using adjacent primary standards.

- Web: OWASP Top 10:2025 + OWASP API Top 10:2023 + selected CWE Top 25:2025 items.
- Desktop: OWASP Desktop Top 10 + selected CWE Top 25:2025 items.
- Mobile: OWASP Mobile Top 10:2024 + selected OWASP MASWE items.
- Web3: OWASP Smart Contract Top 10:2026 + OWASP Web3 Attack Vectors Top 15.
- API: OWASP API Top 10:2023 + selected CWE Top 25:2025 items.

## Web (25)

1. `A01:2025` Broken Access Control
2. `A02:2025` Security Misconfiguration
3. `A03:2025` Software Supply Chain Failures
4. `A04:2025` Cryptographic Failures
5. `A05:2025` Injection
6. `A06:2025` Insecure Design
7. `A07:2025` Authentication Failures
8. `A08:2025` Software or Data Integrity Failures
9. `A09:2025` Security Logging and Alerting Failures
10. `A10:2025` Mishandling of Exceptional Conditions
11. `API1:2023` Broken Object Level Authorization
12. `API2:2023` Broken Authentication
13. `API3:2023` Broken Object Property Level Authorization
14. `API4:2023` Unrestricted Resource Consumption
15. `API5:2023` Broken Function Level Authorization
16. `API6:2023` Unrestricted Access to Sensitive Business Flows
17. `API7:2023` Server Side Request Forgery
18. `API8:2023` Security Misconfiguration
19. `API9:2023` Improper Inventory Management
20. `API10:2023` Unsafe Consumption of APIs
21. `CWE-79` Cross-site Scripting
22. `CWE-89` SQL Injection
23. `CWE-352` Cross-Site Request Forgery
24. `CWE-22` Path Traversal
25. `CWE-918` Server-Side Request Forgery

## Desktop (25)

1. `DA1` Injections
2. `DA2` Broken Authentication and Session Management
3. `DA3` Sensitive Data Exposure
4. `DA4` Improper Cryptography Usage
5. `DA5` Improper Authorization
6. `DA6` Security Misconfiguration
7. `DA7` Insecure Communication
8. `DA8` Poor Code Quality
9. `DA9` Using Components with Known Vulnerabilities
10. `DA10` Insufficient Logging and Monitoring
11. `CWE-787` Out-of-bounds Write
12. `CWE-416` Use After Free
13. `CWE-125` Out-of-bounds Read
14. `CWE-120` Classic Buffer Overflow
15. `CWE-121` Stack-based Buffer Overflow
16. `CWE-122` Heap-based Buffer Overflow
17. `CWE-476` NULL Pointer Dereference
18. `CWE-502` Deserialization of Untrusted Data
19. `CWE-20` Improper Input Validation
20. `CWE-284` Improper Access Control
21. `CWE-306` Missing Authentication for Critical Function
22. `CWE-862` Missing Authorization
23. `CWE-200` Exposure of Sensitive Information to an Unauthorized Actor
24. `CWE-77` Command Injection
25. `CWE-770` Allocation of Resources Without Limits or Throttling

## Mobile (25)

1. `M1:2024` Improper Credential Usage
2. `M2:2024` Inadequate Supply Chain Security
3. `M3:2024` Insecure Authentication/Authorization
4. `M4:2024` Insufficient Input/Output Validation
5. `M5:2024` Insecure Communication
6. `M6:2024` Inadequate Privacy Controls
7. `M7:2024` Insufficient Binary Protections
8. `M8:2024` Security Misconfiguration
9. `M9:2024` Insecure Data Storage
10. `M10:2024` Insufficient Cryptography
11. `MASWE-0001` Insertion of Sensitive Data into Logs
12. `MASWE-0005` API Keys Hardcoded in the App Package
13. `MASWE-0013` Hardcoded Cryptographic Keys in Use
14. `MASWE-0027` Improper Random Number Generation
15. `MASWE-0038` Authentication Tokens Not Validated
16. `MASWE-0040` Insecure Authentication in WebViews
17. `MASWE-0047` Insecure Identity Pinning
18. `MASWE-0050` Cleartext Traffic
19. `MASWE-0052` Insecure Certificate Validation
20. `MASWE-0058` Insecure Deep Links
21. `MASWE-0067` Debuggable Flag Not Disabled
22. `MASWE-0068` JavaScript Bridges in WebViews
23. `MASWE-0076` Dependencies with Known Vulnerabilities
24. `MASWE-0086` SQL Injection
25. `MASWE-0108` Sensitive Data in Network Traffic

## Web3 (25)

1. `SC01:2026` Access Control Vulnerabilities
2. `SC02:2026` Business Logic Vulnerabilities
3. `SC03:2026` Price Oracle Manipulation
4. `SC04:2026` Flash Loan-Facilitated Attacks
5. `SC05:2026` Lack of Input Validation
6. `SC06:2026` Unchecked External Calls
7. `SC07:2026` Arithmetic Errors (Rounding and Precision)
8. `SC08:2026` Reentrancy Attacks
9. `SC09:2026` Integer Overflow and Underflow
10. `SC10:2026` Proxy and Upgradeability Vulnerabilities
11. `WA01` Multisig Hijacking
12. `WA02` Supply Chain Attacks (npm, PyPI, OSS)
13. `WA03` Private Key Compromise (PKC)
14. `WA04` Drainer Malware and Drainer-as-a-Service (DaaS)
15. `WA05` Fake Interview and Video Call Social Engineering
16. `WA06` UI/UX Spoofing and Approval Phishing
17. `WA07` Centralised Exchange and Web2/2.5 Infrastructure Breaches
18. `WA08` Phishing and General Social Engineering
19. `WA09` Romance, Investment, Impersonation, Recovery and Pig Butchering Scams
20. `WA10` Rug Pulls, Fake Airdrops and Token Impersonation
21. `WA11` Wrench Attacks and Physical Coercion
22. `WA12` Insider Threats and Collusive Abuse
23. `WA13` DNS, Domain and Routing Infrastructure Hijacking
24. `WA14` Wallet Software, Extension and App Compromises
25. `WA15` Nation-State Infiltration via Fake Hiring and Malicious OSS Contributions

## API (25)

1. `API1:2023` Broken Object Level Authorization
2. `API2:2023` Broken Authentication
3. `API3:2023` Broken Object Property Level Authorization
4. `API4:2023` Unrestricted Resource Consumption
5. `API5:2023` Broken Function Level Authorization
6. `API6:2023` Unrestricted Access to Sensitive Business Flows
7. `API7:2023` Server Side Request Forgery
8. `API8:2023` Security Misconfiguration
9. `API9:2023` Improper Inventory Management
10. `API10:2023` Unsafe Consumption of APIs
11. `CWE-862` Missing Authorization
12. `CWE-863` Incorrect Authorization
13. `CWE-639` Authorization Bypass Through User-Controlled Key
14. `CWE-306` Missing Authentication for Critical Function
15. `CWE-200` Exposure of Sensitive Information to an Unauthorized Actor
16. `CWE-918` Server-Side Request Forgery
17. `CWE-20` Improper Input Validation
18. `CWE-89` SQL Injection
19. `CWE-79` Cross-site Scripting
20. `CWE-352` Cross-Site Request Forgery
21. `CWE-434` Unrestricted Upload of File with Dangerous Type
22. `CWE-502` Deserialization of Untrusted Data
23. `CWE-77` Command Injection
24. `CWE-78` OS Command Injection
25. `CWE-770` Allocation of Resources Without Limits or Throttling

## Primary Source Links

- OWASP Top 10:2025: <https://owasp.org/Top10/2025/>
- OWASP API Security Top 10:2023: <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP Desktop App Security Top 10: <https://owasp.org/www-project-desktop-app-security-top-10/>
- OWASP Mobile Top 10:2024: <https://owasp.org/www-project-mobile-top-10/>
- OWASP MASWE Index: <https://mas.owasp.org/MASWE/index.html>
- OWASP Smart Contract Top 10:2026: <https://owasp.org/www-project-smart-contract-top-10/>
- OWASP Web3 Attack Vectors Top 15: <https://scs.owasp.org/sctop10/Web3-Attack-Vectors-Top15/>
- MITRE CWE Top 25:2025: <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>
