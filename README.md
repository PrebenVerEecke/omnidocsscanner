# NewgenONE Pentest Tool

A comprehensive CLI security testing tool for discovering misconfigurations and vulnerabilities in Omnidocs NewgenONE deployments.

## ⚠️ Legal Notice

This tool is intended for **authorized security testing only**. Use only on systems you have explicit permission to test. The tool is designed to minimize impact and respect rate limits. Unauthorized use may violate laws and terms of service.

## Features

- 🔍 **Unauthenticated Discovery**: Health endpoints, API docs, open directories, security headers
- 🔐 **Authentication Support**: Form-based and JWT authentication
- 🛡️ **Security Checks**: CORS, CSRF, IDOR/BOLA, headers, JWT analysis
- 📊 **Multiple Output Formats**: Console (colored table), JSON, SARIF, JUnit
- ⚡ **Performance**: Rate limiting, concurrency control, timeouts
- 🔧 **Extensible**: Plugin-based architecture for adding new checks

## Installation

### From Source

```bash
git clone <repository>
cd newgenone-pentest
make build
```

### Using Go Install

```bash
go install github.com/your-org/newgenone-pentest@latest
```

## Usage

### Basic Unauthenticated Scan

```bash
newgenone-pentest --base-url https://newgen.example.com --unauth
```

### Full Authenticated Scan

```bash
newgenone-pentest --base-url https://newgen.example.com --cabinet newgenso
```

### With Credentials

```bash
newgenone-pentest \
  --base-url https://newgen.example.com \
  --username alice \
  --password 'S3cret!' \
  --cabinet newgenso \
  --output-json findings.json
```

### Advanced Usage

```bash
newgenone-pentest \
  --base-url https://newgen.example.com \
  --cabinet newgenso \
  --concurrency 5 \
  --rate-limit 3.0 \
  --timeout 30s \
  --proxy http://proxy.example.com:8080 \
  --output-json report.json \
  --output-sarif findings.sarif \
  --verbose
```

### Enable Dangerous Tests

```bash
newgenone-pentest \
  --base-url https://newgen.example.com \
  --dangerous \
  --max-ids 50
```

## Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--base-url` | Target NewgenONE URL (required) | - |
| `--cabinet` | Default cabinet name | `newgenso` |
| `--username` | Authentication username | - |
| `--password` | Authentication password | - |
| `--auth` | Run authenticated checks | `true` |
| `--unauth` | Run unauthenticated checks | `true` |
| `--include` | Extra paths to include | `[]` |
| `--exclude` | Paths to exclude (glob/regex) | `[]` |
| `--timeout` | Request timeout | `10s` |
| `--concurrency` | Max concurrent requests | `10` |
| `--rate-limit` | Rate limit (requests/sec) | `5.0` |
| `--proxy` | HTTP proxy URL | - |
| `--insecure-tls` | Skip TLS verification | `false` |
| `--output-json` | JSON output file | - |
| `--output-sarif` | SARIF output file | - |
| `--output-junit` | JUnit XML output file | - |
| `--dangerous` | Enable state-changing tests | `false` |
| `--max-ids` | Max IDs for IDOR/BOLA testing | `100` |
| `-q, --quiet` | Quiet mode | `false` |
| `-v, --verbose` | Verbose output | `false` |

## Environment Variables

You can set configuration via environment variables:

```bash
export NEWGEN_BASE_URL=https://newgen.example.com
export NEWGEN_USER=alice
export NEWGEN_PASS=S3cret!
```

## Output Formats

### Console Output
Color-coded table with findings sorted by severity:

```
🔍 NewgenONE Security Assessment Report
Target: https://newgen.example.com
Generated: 2024-01-15T10:30:00Z
Total Findings: 5

┌──────────┬─────────────────┬────────────┬─────────────────────────────────┬─────────────────────────────────┐
│ Severity │ Check           │ Endpoint   │ Title                           │ Summary                         │
├──────────┼─────────────────┼────────────┼─────────────────────────────────┼─────────────────────────────────┤
│ CRITICAL │ cors-misconfig  │ /          │ Critical CORS Misconfiguration │ Wildcard origin with credentia… │
│ HIGH     │ api-docs-discov │ /swagger   │ API Documentation Exposed      │ Swagger UI interface accessible │
│ MEDIUM   │ headers-missing │ /          │ Missing Security Headers       │ X-Frame-Options not present    │
└──────────┴─────────────────┴────────────┴─────────────────────────────────┴─────────────────────────────────┘
```

### JSON Output
Complete structured data for programmatic processing:

```json
{
  "title": "NewgenONE Security Assessment",
  "timestamp": "2024-01-15T10:30:00Z",
  "base_url": "https://newgen.example.com",
  "findings": [...],
  "summary": {
    "total_findings": 5,
    "severity_count": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 3}
  }
}
```

### SARIF Output
Standardized format for CI/CD integration:

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [...]
}
```

## Security Checks

### Unauthenticated Checks
- **Header Analysis**: Server disclosure, security headers, CORS
- **API Discovery**: Swagger/OpenAPI docs, health endpoints
- **Directory Enumeration**: Open directories, backup files
- **Information Disclosure**: Version info, stack traces

### Authenticated Checks
- **Access Control**: IDOR/BOLA testing across cabinets
- **CSRF Protection**: Token validation, SameSite analysis
- **JWT Security**: Token analysis, expiration checks
- **Session Management**: Cookie security, timeout validation
- **File Operations**: Upload/download security (when `--dangerous` enabled)

## Architecture

The tool uses a modular plugin architecture:

```
internal/
├── auth/         # Authentication handlers
├── checks/       # Security check implementations
├── client/       # HTTP client with rate limiting
├── report/       # Output formatters
├── session/      # Session management
└── util/         # Utility functions
```

Adding new checks is simple - implement the `Check` interface and register it.

## Development

### Prerequisites
- Go 1.21+
- make

### Setup
```bash
make dev-setup
```

### Build
```bash
make build
```

### Test
```bash
make test
make test-coverage
```

### Quality Checks
```bash
make check  # fmt, vet, lint, test
```

### Release
```bash
make release
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all checks pass: `make check`
5. Submit a pull request

## License

See LICENSE file for details.

## Support

For issues and questions:
- Create an issue on GitHub
- Check the documentation
- Review the code for implementation details

---

**Remember**: This tool is for authorized security testing only. Always obtain written permission before testing any system.
