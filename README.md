# PSSO IdP Proxy Server (Java)

[![Maven Build and Release](https://github.com/Muthu-Opensource-Solutions/psso-idp-proxy-server-java/actions/workflows/release.yml/badge.svg)](https://github.com/Muthu-Opensource-Solutions/psso-idp-proxy-server-java/actions/workflows/release.yml)

---

## 1. Introduction & Requirements

### Overview
This project is a server-side proxy implementation designed to work with Apple's **macOS Platform Single Sign-On (Platform SSO / PSSO)** framework.

While Apple's PSSO framework is often used for full device-level SSO, the primary goal of this proxy server is to utilize the **Password Synchronization** feature of the framework. It enables users' local macOS account passwords to synchronize seamlessly with your Identity Provider (IdP) without requiring full device-level SSO enrollment.

This server acts as a proxy between macOS Platform SSO and your standard OpenID Connect (OIDC) Identity Provider (e.g., Okta, Microsoft Entra ID, Ping Identity, Keycloak, etc.).

> **Companion macOS Client**:  
> This server requires the companion client application running on macOS:  
> 👉 [psso-client-swiftui](https://github.com/Muthu-Opensource-Solutions/psso-client-swiftui)

---

### Prerequisites & Requirements

1. **Network Accessibility**:
   - The server must be accessible over HTTPS on port `443`.
   - It must be reachable via a domain name (`<DOMAIN_FQDN>`, e.g., `psso.example.com`) either over the public internet or within the local network accessible by the test macOS client devices.

2. **TLS / SSL Certificate Trust (Apple System Root CA)**:
   - The server **must have TLS enabled** on port `443`.
   - **Crucial Apple Platform SSO Requirement**: The Certificate Authority (CA) that signs your server's certificate **must be trusted in the macOS System Root Keychain** (see [Apple's List of Available Trusted Root Certificates](https://support.apple.com/en-in/103272)).
   - ⚠️ **Important**: Apple's Platform SSO framework **rejects** self-signed certificates and certificates whose CAs were installed via MDM configuration profiles. A publicly trusted CA certificate (such as Let's Encrypt, DigiCert, Sectigo, etc.) is strictly required.

3. **Identity Provider (IdP) Support**:
   - Your Identity Provider must support standard OpenID Connect (OIDC) with:
     - **Authorization Code Flow** (`grant_type: authorization_code`) for user registration.
     - **Resource Owner Password Credentials Flow** (`grant_type: password` / ROPG) for password verification and synchronization.

---

### Obtaining and Loading the Docker Image

Pre-built multi-architecture Docker images are published in the **[Releases](https://github.com/Muthu-Opensource-Solutions/psso-idp-proxy-server-java/releases)** section of this repository.

1. **Download the archive matching your server host architecture**:
   - For Intel / AMD 64-bit servers (`x86_64`): `psso-idp-proxy-server-java-<TAG>-amd64.tar.gz`
   - For Apple Silicon Macs / ARM 64-bit servers (`arm64`): `psso-idp-proxy-server-java-<TAG>-arm64.tar.gz`

2. **Decompress the downloaded archive**:
   ```bash
   gunzip psso-idp-proxy-server-java-<TAG>-<ARCH>.tar.gz
   ```

3. **Load the Docker image into your host Docker daemon**:
   ```bash
   docker load -i psso-idp-proxy-server-java-<TAG>-<ARCH>.tar
   ```

4. **Verify the loaded image**:
   ```bash
   docker images psso-idp-proxy-server-java
   ```
   *Note the image repository and tag (e.g., `psso-idp-proxy-server-java:<TAG>`).*

---

## 2. Environment Variables & Configuration Guide

Before starting the server, prepare the required files and environment variables as described below.

### A. Host Domain & TLS Keystore

| Variable | Description |
| :--- | :--- |
| `SSL_KEYSTORE_PASSWORD` | Password used to secure the PKCS#12 (`.p12`) certificate keystore. |

#### Preparing `certs.p12`:
The Tomcat container expects a PKCS#12 keystore file named `certs.p12` mounted at `/usr/local/tomcat/ssl/certs.p12`.

If you have standard PEM certificate files (`fullchain.pem` and `privkey.pem`):
```bash
openssl pkcs12 -export \
  -in fullchain.pem \
  -inkey privkey.pem \
  -out certs.p12 \
  -password pass:<YOUR_SSL_KEYSTORE_PASSWORD>
```
*Choose a strong password and save it as your `SSL_KEYSTORE_PASSWORD`.*

---

### B. OIDC Application 1: User Registration (Authorization Code Flow)

In your Identity Provider, create an OIDC Application dedicated to interactive user registration.

- **Grant Type**: `authorization_code`
- **Allowed Scopes**: `openid`, `offline_access`, `email`, `profile`
- **Redirect URI**: `https://<DOMAIN_FQDN>/oidc/authCode/userRegistrationCallback`
- **Assignment**: Assign this application to your target users/groups.

Collect the following variables from your IdP:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `PSSO_AUTH_CODE_GRANT_OIDC_PROVIDER_URL` | Full OIDC Issuer URL for the IdP | `https://identity.example.com` |
| `PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_ID` | Client ID of the Auth Code application | `0oab1c2d3e4f5g6h7i8j` |
| `PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_SECRET` | Client Secret of the Auth Code application | `SecretKeySample123` |

---

### C. OIDC Application 2: Password Verification / Sync (ROPG Flow)

In your Identity Provider, create or configure an OIDC Application dedicated to direct password verification.

- **Grant Type**: `password` (Resource Owner Password Credentials / ROPC)
- **Allowed Scopes**: `openid`, `offline_access`, `email`, `profile`
- **Assignment**: Assign this application to your target users/groups.

Collect the following variables from your IdP:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `PSSO_ROPG_OIDC_PROVIDER_URL` | Full OIDC Issuer URL for the ROPG application | `https://identity.example.com` |
| `PSSO_ROPG_CLIENT_ID` | Client ID of the ROPG application | `0oax9y8z7w6v5u4t3s2r` |
| `PSSO_ROPG_CLIENT_SECRET` | Client Secret of the ROPG application | `SecretKeySample456` |

> **Single Application vs. Two Applications**:  
> Both flows can technically share the same OIDC application if your IdP allows both `authorization_code` and `password` grant types on a single client.  
> However, **having two separate applications is strongly recommended**:
> - **Application 1 (Registration)** allows interactive web logins, supporting MFA, WebAuthn/FIDO2, and conditional access policies.
> - **Application 2 (Password Sync)** performs automated backend username/password validation, which requires an authentication policy without interactive MFA prompts.

---

### D. Server Storage & Internal Security Keys

| Variable | Description | Example |
| :--- | :--- | :--- |
| `SERVER_FILES_STORAGE_DIRECTORY` | Path inside the container where server keys and device registrations are stored. Must be set to `/data`. | `/data` |
| `PSSO_SERVER_KEY_PROTECTION_PASSWORD` | Strong password used to encrypt the server's private EC signing key (`serverSigningKey.jwe`). | Random secret string |
| `PSSO_HMAC_SECRET_KEY` | Shared secret between this server and the [psso-client-swiftui](https://github.com/Muthu-Opensource-Solutions/psso-client-swiftui) app. | Shared secret string |
| `PSSO_OIDC_CUSTOM_SCOPES` *(Optional)* | Any additional custom scopes required by your IdP (separated by space). | `""` |

#### Tips:
- Generate a secure random string for `PSSO_SERVER_KEY_PROTECTION_PASSWORD`:
  ```bash
  openssl rand -base64 32
  ```
- Generate a shared secret for `PSSO_HMAC_SECRET_KEY`:
  ```bash
  openssl rand -hex 32
  ```
  *Distribute this same secret to the macOS client app via your MDM Extensible SSO payload to ensure only managed devices can register.*

---

### E. Host Mount Directories

Create the required directories on your host machine to store persistent data, logs, and your certificate:

```bash
mkdir -p /opt/psso/data
mkdir -p /opt/psso/logs
cp certs.p12 /opt/psso/certs.p12
```

| Host Path | Container Mount Path | Purpose |
| :--- | :--- | :--- |
| `/opt/psso/data` | `/data` | Stores `serverSigningKey.jwe` and enrolled device registration keys. Persists across container restarts. |
| `/opt/psso/logs` | `/logs` | Stores Tomcat catalina and HTTP access logs. |
| `/opt/psso/certs.p12` | `/usr/local/tomcat/ssl/certs.p12` | Mounted PKCS#12 SSL certificate keystore. |

---

## 3. Running the Server with Docker

Run the container using `docker run`, substituting the placeholder values with your actual configuration:

```bash
docker run -d \
  --name psso-proxy-idp-server-java \
  --restart unless-stopped \
  -p 443:443 \
  -e SSL_KEYSTORE_PASSWORD="<YOUR_SSL_KEYSTORE_PASSWORD>" \
  -e SERVER_FILES_STORAGE_DIRECTORY="/data" \
  -e PSSO_AUTH_CODE_GRANT_OIDC_PROVIDER_URL="https://<YOUR_IDP_ISSUER_URL>" \
  -e PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_ID="<YOUR_AUTH_CODE_CLIENT_ID>" \
  -e PSSO_AUTH_CODE_GRANT_OIDC_CLIENT_SECRET="<YOUR_AUTH_CODE_CLIENT_SECRET>" \
  -e PSSO_ROPG_OIDC_PROVIDER_URL="https://<YOUR_IDP_ISSUER_URL>" \
  -e PSSO_ROPG_CLIENT_ID="<YOUR_ROPG_CLIENT_ID>" \
  -e PSSO_ROPG_CLIENT_SECRET="<YOUR_ROPG_CLIENT_SECRET>" \
  -e PSSO_SERVER_KEY_PROTECTION_PASSWORD="<GENERATED_SERVER_KEY_PROTECTION_PASSWORD>" \
  -e PSSO_HMAC_SECRET_KEY="<SHARED_HMAC_SECRET_KEY>" \
  -v /opt/psso/data:/data \
  -v /opt/psso/logs:/logs \
  -v /opt/psso/certs.p12:/usr/local/tomcat/ssl/certs.p12 \
  psso-idp-proxy-server-java:<TAG>
```

---

### Verification & Health Check

1. **Check Container Logs**:
   ```bash
   docker logs -f psso-proxy-idp-server-java
   ```
   Or inspect access logs in your host logs directory:
   ```bash
   tail -f /opt/psso/logs/localhost_access_log.*.txt
   ```

2. **Verify Apple App Site Association**:
   Test that the server is serving requests over HTTPS from your client machine:
   ```bash
   curl -i https://<DOMAIN_FQDN>/.well-known/apple-app-site-association
   ```
   Expected response:
   ```json
   {"authsrv":{"apps":["84V944P795.com.muthuopensource.psso-client-swiftui"]}}
   ```

---

## 4. Commercials & Consultation

For any commercial inquiries, custom deployments, or professional consultation, please reach out at:

📧 **[muthurajwork@zohomail.in](mailto:muthurajwork@zohomail.in)**
