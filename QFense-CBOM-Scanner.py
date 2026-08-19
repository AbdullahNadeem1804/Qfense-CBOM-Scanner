import ast
import os
import json
import re
from datetime import datetime, timezone
import linecache 

class PythonCryptoVisitor(ast.NodeVisitor):
    def __init__(self, filepath):
        self.filepath = filepath
        self.findings = []

    def visit_ImportFrom(self, node):
        if node.module and 'cryptography.hazmat.primitives.asymmetric' in node.module:
            for alias in node.names:
                if alias.name in ['rsa', 'ec', 'dsa']:
                    self.findings.append({
                        "language": "Python",
                        "type": "algorithm",
                        "name": alias.name.upper(),
                        "file": self.filepath,
                        "line": node.lineno,
                        "status": "Vulnerable to Post-Quantum Attacks"
                    })
        self.generic_visit(node)

def scan_java_go_file(filepath, file_content):
    findings = []
    lines = file_content.split('\n')
    
    # Regex patterns for Java and Go crypto libraries
    patterns = {
        "Java": [(r'import\s+(javax\.crypto\..*|java\.security\..*RSA.*|org\.bouncycastle\..*)', 'Legacy Java Crypto')],
        "Go": [(r'import\s+.*"crypto/(rsa|ecdsa|dsa)"', 'Legacy Go Crypto')]
    }

    ext = ".java" if filepath.endswith(".java") else ".go"
    lang = "Java" if ext == ".java" else "Go"

    for i, line in enumerate(lines):
        for pattern, name in patterns[lang]:
            if re.search(pattern, line):
                findings.append({
                    "language": lang,
                    "type": "library-import",
                    "name": name,
                    "file": filepath,
                    "line": i + 1,
                    "status": "Requires FIPS 203/204 review"
                })
    return findings

def scan_directory(directory_path):
    all_findings = []
    for root, dirs, files in os.walk(directory_path):
        # Ignore hidden directories like .git so it runs faster and cleaner
        if '.git' in dirs:
            dirs.remove('.git')
            
        for file in files:
            # ONLY open the file if it's a language we care about
            if not file.endswith(('.py', '.java', '.go')):
                continue
                
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                if file.endswith('.py'):
                    tree = ast.parse(content, filename=filepath)
                    visitor = PythonCryptoVisitor(filepath)
                    visitor.visit(tree)
                    all_findings.extend(visitor.findings)
                elif file.endswith('.java') or file.endswith('.go'):
                    all_findings.extend(scan_java_go_file(filepath, content))
            except Exception:
                # Silently skip any weird files to keep the terminal clean
                pass
    return all_findings

def generate_cbom(findings):
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tools": [{"vendor": "QFense", "name": "Polyglot-CBOM-Scanner"}]
        },
        "components": []
    }
    
    MAX_DISPLAY = 4 # Limits the terminal output for a clean screenshot
    
    for i, finding in enumerate(findings):
        algo = finding['name'].upper()
        
        # Specific NIST Remediation Advice
        if algo == 'RSA':
            threat_desc = "Integer Factorization Risk. Migrate to FIPS 203 (ML-KEM)."
        elif algo == 'EC':
            threat_desc = "Discrete Log Risk. Migrate to FIPS 204 (ML-DSA)."
        elif algo in ['DSA', 'ED25519', 'ED448']:
            threat_desc = "Deprecated Signature. Migrate to FIPS 205 (SLH-DSA)."
        else:
            threat_desc = "Legacy Primitive. Fails NIST Post-Quantum Standards."
            
        finding['status'] = threat_desc # Update the JSON status too
        
        # Only print the first MAX_DISPLAY items to the terminal
        if i < MAX_DISPLAY:
            code_snippet = linecache.getline(finding['file'], finding['line']).strip()
            print(f"\n[🚨] PQC-VIOLATION DETECTED: {algo} Cryptography")
            print(f" ├─ Target:  {finding['file']}:{finding['line']}")
            print(f" ├─ Context: `{code_snippet}`")
            print(f" └─ Threat:  {threat_desc}")
            
        cbom["components"].append({
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-asset-{i}",
            "name": algo,
            "properties": [
                {"name": "language", "value": finding["language"]},
                {"name": "file_location", "value": finding["file"]},
                {"name": "line_number", "value": str(finding["line"])},
                {"name": "pqc_status", "value": finding["status"]}
            ]
        })
        
    if len(findings) > MAX_DISPLAY:
        print(f"\n... and {len(findings) - MAX_DISPLAY} more legacy assets suppressed for terminal readability.")
        
    return json.dumps(cbom, indent=4)

if __name__ == "__main__":
    # Pointed to the scanning folder
    target_dir = "./paramiko" 
    print(f"Scanning {target_dir} for cryptographic assets...\n")
    results = scan_directory(target_dir)
    
    if not results:
        print("No vulnerable assets found. Ensure your target files contain standard crypto imports.")
    else:
        with open("qfense_cbom.json", "w") as f:
            f.write(generate_cbom(results))
        print(f"\nFound {len(results)} assets. CBOM saved to qfense_cbom.json")