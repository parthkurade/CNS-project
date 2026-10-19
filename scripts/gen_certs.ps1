# PhishShield – TLS Certificate Generator (Windows PowerShell)
# Generates a self-signed CA + server cert for local development.
# Run this ONCE before starting the server.
# Output: certs/ca.crt, certs/server.crt, certs/server.key
#
# For Linux/macOS, use scripts/gen_certs.sh instead.

param(
    [string]$CertsDir = "certs",
    [string]$Hostname = "localhost",
    [int]$ValidDays = 365
)

$ErrorActionPreference = "Stop"

# Check for openssl
$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) {
    # Try Git's bundled openssl
    $gitOpenssl = "C:\Program Files\Git\usr\bin\openssl.exe"
    if (Test-Path $gitOpenssl) {
        $openssl = $gitOpenssl
    } else {
        Write-Error "openssl not found. Install Git for Windows or OpenSSL."
        exit 1
    }
} else {
    $openssl = "openssl"
}

New-Item -ItemType Directory -Path $CertsDir -Force | Out-Null

Write-Host "Generating CA private key..." -ForegroundColor Cyan
& $openssl genrsa -out "$CertsDir\ca.key" 4096

Write-Host "Generating CA certificate..." -ForegroundColor Cyan
& $openssl req -new -x509 -days $ValidDays -key "$CertsDir\ca.key" -out "$CertsDir\ca.crt" `
    -subj "/C=IN/ST=Maharashtra/L=Mumbai/O=ZeroTrace-SPIT/CN=PhishShield-CA"

Write-Host "Generating server private key..." -ForegroundColor Cyan
& $openssl genrsa -out "$CertsDir\server.key" 2048

Write-Host "Generating server CSR..." -ForegroundColor Cyan
& $openssl req -new -key "$CertsDir\server.key" -out "$CertsDir\server.csr" `
    -subj "/C=IN/ST=Maharashtra/L=Mumbai/O=ZeroTrace-SPIT/CN=$Hostname"

# SAN extension
$extFile = "$CertsDir\server.ext"
@"
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
subjectAltName = @alt_names
[SAN]
subjectAltName = DNS:$Hostname,DNS:localhost,IP:127.0.0.1
"@ | Out-File -FilePath $extFile -Encoding ASCII

Write-Host "Signing server certificate with CA..." -ForegroundColor Cyan
& $openssl x509 -req -days $ValidDays -in "$CertsDir\server.csr" `
    -CA "$CertsDir\ca.crt" -CAkey "$CertsDir\ca.key" -CAcreateserial `
    -out "$CertsDir\server.crt" `
    -extfile $extFile -extensions SAN

Remove-Item "$CertsDir\server.csr", $extFile -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "✓ Certificates generated in $CertsDir/" -ForegroundColor Green
Write-Host "  CA cert:     $CertsDir\ca.crt" -ForegroundColor Gray
Write-Host "  Server cert: $CertsDir\server.crt" -ForegroundColor Gray
Write-Host "  Server key:  $CertsDir\server.key" -ForegroundColor Gray
Write-Host ""
Write-Host "To trust the CA locally (Chrome/Edge):" -ForegroundColor Yellow
Write-Host "  Import $CertsDir\ca.crt into 'Trusted Root Certification Authorities'" -ForegroundColor Yellow
Write-Host ""
Write-Host "WARNING: These are development certs only. Never use in production." -ForegroundColor Red
