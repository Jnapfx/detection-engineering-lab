# Security Mitigations

Following the investigation of suspicious authentication activity detected in Microsoft Sentinel, several security hardening measures are recommended to reduce the risk of brute-force attacks.

---

## 1. Configure Account Lockout Policy

Limit the number of failed authentication attempts before an account is temporarily locked.

Recommended configuration:

* Account lockout threshold: 5 failed attempts
* Account lockout duration: 15 minutes
* Reset counter after: 15 minutes

Security benefit:
Prevents attackers from attempting unlimited password guesses.

---

## 2. Restrict RDP Access

Remote Desktop Protocol (RDP) should not be openly exposed to the internet.

Recommended actions:

* Restrict inbound RDP access to trusted IP ranges
* Disable RDP when not required
* Monitor authentication attempts from unknown sources

Security benefit:
Reduces attack surface and prevents automated scanning and brute-force attempts.

---

## 3. Harden Network Security Rules

Azure Network Security Groups (NSGs) should restrict unnecessary inbound traffic.

Recommended actions:

* Restrict port 3389 (RDP)
* Allow administrative access only from trusted networks
* Monitor abnormal connection attempts

Security benefit:
Reduces exposure of remote services to external attackers.

---

## 4. Implement Multi-Factor Authentication (MFA)

Enable MFA for accounts that access systems remotely or have administrative privileges.

Security benefit:
Even if passwords are compromised, attackers cannot authenticate without the second factor.

---

These mitigations align with common defensive strategies used in SOC environments and help strengthen the overall security posture of the system.

---

End of document
