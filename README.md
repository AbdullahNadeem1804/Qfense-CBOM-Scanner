# QFense CBOM Scanner 

A lightweight, polyglot static analysis engine designed to discover legacy cryptographic assets across complex codebases and generate a standard CycloneDX 1.6 Cryptographic Bill of Materials (CBOM).

## The Context
With the recent finalization of NIST's Post-Quantum Cryptography (PQC) standards (FIPS 203, 204, and 205), the cybersecurity industry is beginning the massive transition away from vulnerable public-key encryption like RSA and ECC. 

However, before teams can migrate to quantum-safe algorithms, they must first discover where legacy cryptography is buried within their monolithic architectures. **You cannot secure what you cannot see.** 

QFense was built as an independent research tool to solve this discovery bottleneck.

## Features
*   **Multi-Language Parsing:** Natively scans Python (via robust AST parsing), as well as Java and Go (via regex pattern matching).
*   **CycloneDX 1.6 Compliant:** Automatically exports findings into a standardized, machine-readable JSON format ready for enterprise compliance workflows.
*   **Zero Dependencies:** Runs entirely locally with standard Python libraries. No external API calls, ensuring your proprietary source code remains completely private.
*   **Enterprise-Tested:** Successfully maps massive, real-world architectures (tested against EFF's `certbot` and `paramiko`).

## Usage

1. Clone this repository to your local machine:
   ```bash
   git clone [https://github.com/yourusername/qfense-cbom-scanner.git](https://github.com/yourusername/qfense-cbom-scanner.git)
   cd qfense-cbom-scanner

2. Open QFense-CBOM-Scanner.py and modify the target_dir variable to point to the repository you wish to audit.

3. Run the scanner:

  ```bash
  python QFense-CBOM-Scanner.py
  ```

### Example Terminal Output
When run against a target, the scanner will extract the vulnerable code snippet and map it to the specific NIST remediation standard before generating the final JSON artifact:

```text
Scanning ./certbot for cryptographic assets...

[🚨] PQC-VIOLATION DETECTED: RSA Cryptography
 ├─ Target:  ./certbot/acme/examples/http01_example.py:33
 ├─ Context: `from cryptography.hazmat.primitives.asymmetric import rsa`
 └─ Threat:  Integer Factorization Risk. Migrate to FIPS 203 (ML-KEM).

[🚨] PQC-VIOLATION DETECTED: EC Cryptography
 ├─ Target:  ./certbot/certbot/src/certbot/crypto_util.py:23
 ├─ Context: `from cryptography.hazmat.primitives.asymmetric import ec`
 └─ Threat:  Discrete Log Risk. Migrate to FIPS 204 (ML-DSA).

... and 14 more legacy assets suppressed for terminal readability.
```

## Remediation & Outreach
Generating a CBOM is only the first step. Safely replacing legacy encryption with NIST-approved PQC algorithms (like ML-KEM) requires careful integration to avoid breaking existing system architecture.

If your team ran this tool and discovered extensive vulnerabilities, feel free to reach out. I occasionally partner with organizations to run deep-dive vulnerability assessments and execute PQC migration roadmaps.
