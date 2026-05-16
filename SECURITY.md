# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ferret-scan, please **do not open a public GitHub issue**. Instead, report it privately:

**Email:** bshannon@gmail.com  
**Subject line:** `[ferret-scan] Security Vulnerability Report`

Include in your report:
- Description of the vulnerability
- Steps to reproduce (proof-of-concept if available)
- Versions affected
- Potential impact

We will acknowledge your report within **48 hours** and aim to provide an initial assessment within **7 days**. We follow a **90-day responsible disclosure** window — we ask that you keep the vulnerability private for 90 days from the date of our acknowledgement to allow time for a fix and coordinated disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✓ Current |
| 1.x     | ✗ End of life |
| < 1.0   | ✗ Not supported |

## Security Model

ferret-scan is a **static analysis tool**. It reads files and reports findings; it never connects to external networks during scanning (threat intelligence feeds are optional and user-configured).

### Threat Surface

| Surface | Description | Mitigation |
|---------|-------------|------------|
| Scanned files | Files could contain adversarial regex or obfuscated content | All regex patterns bounded (`safeRegex.ts`); file size capped |
| Config files | `.ferretrc.json` could be crafted maliciously | Zod schema validation via `schemas.ts` |
| Custom rules | User-supplied patterns could trigger ReDoS | All user patterns compiled via `compileSafePattern`, which rejects nested quantifiers and screens for known ReDoS triggers before `new RegExp()` is called |
| Quarantine dir | Quarantined files contain attacker-controlled content | Directory created with mode `0700`; path traversal blocked |
| Threat feeds | External indicator databases could be compromised | Feeds are user-opt-in; schema-validated on load |

### Out of Scope for Bug Bounty

- Findings that require the attacker to already have write access to the scanned repository
- Denial-of-service through extremely large (>10 MB) files (file size is configurable)
- Issues in dependencies not imported by ferret-scan

## Security Features

- **Bounded regex execution** — all pattern matching runs under time and match-count limits
- **ReDoS prevention** — `compileSafePattern` screens for nested quantifiers before compiling
- **Glob injection prevention** — `globToRegex` escapes metacharacters and anchors patterns
- **Path traversal prevention** — all file writes validated via `pathSecurity.ts`
- **Quarantine isolation** — quarantined files stored in a mode-700 directory
- **Memory bounds** — `BoundedContentCache` caps in-memory file content at 256 MB aggregate
- **Schema validation** — all config and database files validated through Zod schemas

## Security Contacts

Primary: bshannon@gmail.com
