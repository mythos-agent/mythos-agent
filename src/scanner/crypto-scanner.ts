import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

interface CryptoRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}

const CRYPTO_RULES: CryptoRule[] = [
  {
    id: "crypto-weak-hash",
    title: "Crypto: Weak Hash Algorithm (MD5/SHA1)",
    description: "MD5 and SHA1 are cryptographically broken. Use SHA-256 or SHA-3 for hashing.",
    severity: "high",
    cwe: "CWE-328",
    patterns: [
      /createHash\s*\(\s*["'](?:md5|sha1|md4|ripemd160)["']/gi,
      /hashlib\.(?:md5|sha1)\s*\(/gi,
      /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1|SHA1)["']/gi,
    ],
  },
  {
    id: "crypto-weak-cipher",
    title: "Crypto: Weak Cipher Algorithm",
    description:
      "DES, RC4, and Blowfish are considered broken. Use AES-256-GCM or ChaCha20-Poly1305.",
    severity: "high",
    cwe: "CWE-327",
    patterns: [
      /createCipher(?:iv)?\s*\(\s*["'](?:des|rc4|blowfish|rc2|des-ede)/gi,
      /Cipher\.getInstance\s*\(\s*["'](?:DES|RC4|Blowfish|RC2|DESede)/gi,
      /(?:DES|RC4|Blowfish)\.new\s*\(/gi,
    ],
  },
  {
    id: "crypto-ecb-mode",
    title: "Crypto: ECB Block Cipher Mode",
    description:
      "ECB mode does not provide semantic security — identical plaintext blocks produce identical ciphertext. Use GCM or CBC with HMAC.",
    severity: "high",
    cwe: "CWE-327",
    patterns: [
      /["'](?:aes-\d+-ecb|des-ecb)["']/gi,
      /Cipher\.getInstance\s*\(\s*["']\w+\/ECB/gi,
      /AES\.MODE_ECB/gi,
    ],
  },
  {
    id: "crypto-hardcoded-iv",
    title: "Crypto: Hardcoded Initialization Vector (IV)",
    description:
      "IV/nonce must be unique and random for each encryption operation. Hardcoded IVs break confidentiality.",
    severity: "high",
    cwe: "CWE-329",
    patterns: [
      /(?:iv|nonce|initVector)\s*[:=]\s*(?:Buffer\.from\s*\(|new\s+Uint8Array\s*\()?\s*["']/gi,
      /(?:iv|nonce)\s*[:=]\s*(?:b["']|bytes\s*\()/gi,
    ],
  },
  {
    id: "crypto-hardcoded-key",
    title: "Crypto: Hardcoded Encryption Key",
    description:
      "Encryption key is hardcoded in source code. Use a key management system or derive from secure storage.",
    severity: "critical",
    cwe: "CWE-321",
    patterns: [
      /(?:encryptionKey|secretKey|aesKey|cipherKey|key)\s*[:=]\s*(?:Buffer\.from\s*\()?\s*["'][a-zA-Z0-9+/=]{16,}["']/gi,
      /(?:secret|key)\s*[:=]\s*b["'][a-zA-Z0-9]{16,}["']/gi,
    ],
  },
  {
    id: "crypto-weak-random",
    title: "Crypto: Insecure Random Number Generator",
    description:
      "Math.random() / random() are not cryptographically secure. Use crypto.randomBytes() or secrets module.",
    severity: "high",
    cwe: "CWE-330",
    patterns: [
      /Math\.random\s*\(\s*\).*(?:token|key|secret|password|salt|nonce|session|id)/gi,
      /random\.random\s*\(\s*\).*(?:token|key|secret|password)/gi,
      /rand\.\w+\s*\(\s*\).*(?:token|key|secret)/gi,
    ],
  },
  {
    id: "crypto-timing-attack",
    title: "Crypto: Timing-Vulnerable Comparison",
    description:
      "Using === or == to compare secrets leaks information via timing. Use crypto.timingSafeEqual() or hmac.compare_digest().",
    severity: "medium",
    cwe: "CWE-208",
    patterns: [
      /(?:token|secret|key|hash|password|signature|hmac|digest)\s*===?\s*(?:req|input|provided|expected|stored)/gi,
      /(?:req|input|provided)\.\w*(?:token|secret|key|hash|password|signature)\s*===?\s*/gi,
    ],
  },
  {
    id: "crypto-no-padding",
    title: "Crypto: Cipher Without Proper Padding",
    description:
      "Using NoPadding with block ciphers may leak plaintext length or cause errors. Use PKCS7/OAEP padding.",
    severity: "medium",
    cwe: "CWE-327",
    patterns: [/NoPadding/gi, /padding\s*[:=]\s*(?:false|0|["']none["'])/gi],
  },
  {
    id: "crypto-deprecated-tls",
    title: "Crypto: Deprecated TLS Version",
    description: "TLS 1.0 and 1.1 are deprecated. Use TLS 1.2 or 1.3.",
    severity: "high",
    cwe: "CWE-326",
    patterns: [
      /(?:minVersion|secureProtocol)\s*[:=]\s*["'](?:TLSv1[^.2-3]|SSLv|TLS1_0|TLS1_1)/gi,
      /ssl\.PROTOCOL_TLS(?:v1)?(?:_(?:0|1))?/gi,
      /TLS_1_0|TLS_1_1|SSLv2|SSLv3/gi,
    ],
  },
  {
    id: "crypto-insecure-key-derivation",
    title: "Crypto: Insecure Key Derivation",
    description:
      "Simple hashing for key derivation is insecure. Use PBKDF2, scrypt, or Argon2 with proper iteration count.",
    severity: "high",
    cwe: "CWE-916",
    patterns: [
      /createHash.*(?:password|passwd|secret).*\.digest/gi,
      /hashlib\.sha256\(.*(?:password|passwd)/gi,
    ],
  },
  {
    id: "crypto-small-key-size",
    title: "Crypto: Small Key Size",
    description:
      "Key size is below recommended minimum. Use at least 2048 bits for RSA and 256 bits for symmetric.",
    severity: "medium",
    cwe: "CWE-326",
    patterns: [
      /generateKeyPair.*(?:modulusLength|keySize)\s*[:=]\s*(?:512|768|1024)\b/gi,
      /RSA.*(?:1024|512|768)/gi,
    ],
  },
];

export interface CryptoScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class CryptoScanner {
  async scan(projectPath: string): Promise<CryptoScanResult> {
    const files = await glob(
      ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
      {
        cwd: projectPath,
        absolute: true,
        ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**"],
        nodir: true,
      }
    );

    const findings: Vulnerability[] = [];
    let idCounter = 1;

    for (const file of files) {
      let content: string;
      try {
        const stats = fs.statSync(file);
        if (stats.size > 500_000) continue;
        content = fs.readFileSync(file, "utf-8");
      } catch {
        continue;
      }

      // Quick check
      if (
        !/crypto|cipher|hash|encrypt|decrypt|hmac|sign|verify|ssl|tls|aes|rsa|pbkdf|scrypt|argon|bcrypt|random|Math\.random/i.test(
          content
        )
      ) {
        continue;
      }

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (const rule of CRYPTO_RULES) {
        for (const pattern of rule.patterns) {
          pattern.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            pattern.lastIndex = 0;
            if (pattern.test(lines[i])) {
              findings.push({
                id: `CRYPTO-${String(idCounter++).padStart(4, "0")}`,
                rule: `crypto:${rule.id}`,
                title: rule.title,
                description: rule.description,
                severity: rule.severity,
                category: "crypto",
                cwe: rule.cwe,
                confidence: "high",
                location: {
                  file: relativePath,
                  line: i + 1,
                  snippet: lines[i].trim(),
                },
              });
            }
          }
        }
      }
    }

    return { findings, filesScanned: files.length };
  }
}
