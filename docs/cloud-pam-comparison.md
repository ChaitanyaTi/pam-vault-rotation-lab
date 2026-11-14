# Comparative Analysis: Privileged Access Across Active Directory, Microsoft Entra ID, and AWS IAM

This document compares privileged access architecture, credential models, Just-In-Time (JIT) elevation, and audit capabilities across on-premises Windows Server Active Directory, cloud-native Microsoft Entra ID, and Amazon Web Services (AWS) IAM.

---

## 1. Architectural Comparison Matrix

| Capability | On-Premises Active Directory (AD DS) | Microsoft Entra ID (Azure AD) | Amazon Web Services (AWS IAM) |
| :--- | :--- | :--- | :--- |
| **Identity Entity** | User objects, Computer accounts, gMSAs, Managed Service Accounts | Cloud Users, Service Principals, Managed Identities | IAM Users, IAM Roles, Federated Identities |
| **Privilege Model** | Security Groups (`Domain Admins`, `Enterprise Admins`, custom OUs) | Directory Roles (`Global Administrator`, `User Administrator`) & RBAC | IAM Policies (JSON), Permission Boundaries, SCPs |
| **Credential Type** | Kerberos tickets (TGT/TGS), NTLM hashes, Passwords | OAuth2/OIDC JWT tokens, FIDO2, Windows Hello, Certificates | Short-lived STS tokens, Long-lived Access Key pairs |
| **JIT Mechanism** | AD PAM Optional Feature (`MemberTimeToLive` attribute on group) | Microsoft Entra Privileged Identity Management (PIM) | AWS Security Token Service (`sts:AssumeRole`) with Session Duration |
| **Primary Risk** | Pass-the-Hash, Kerberoasting, standing domain-admin rights | Token theft, OAuth app consent abuse, tenant-wide Global Admin standing rights | Leaked long-lived access keys, IAM privilege escalation, broad `*` policies |
| **Audit Mechanism** | Windows Security Event Logs (4728, 4732, 4724, 4624) on DCs | Entra Audit Logs & Sign-in Logs (Log Analytics / Sentinel) | AWS CloudTrail Event History & AWS Config |

---

## 2. Microsoft Entra ID PIM (Privileged Identity Management) Design Note

> [!NOTE]
> **Licensing & Architecture Note**:
> Just-in-Time (JIT) activation in Microsoft Entra ID natively requires an **Entra ID P2** or **Microsoft 365 E5** license. For organizations operating without P2 licensing, standing role assignments must be mitigated through automated lifecycle scripts or secondary break-glass accounts.

### Production PIM Architectural Blueprint:
1. **Zero Standing Access (Eligible vs Active)**:
   - Administrators (e.g., `alice@lab.local` or test cloud user) are marked as **Eligible** for privileged roles (such as `User Administrator`), rather than permanently **Active**.
2. **Just-In-Time Activation Workflow**:
   - When an administrator requires elevated privileges, they navigate to Entra ID > Privileged Identity Management.
   - Click **Activate** on the target role.
   - Specify activation duration (e.g., 2 hours).
   - Provide mandatory ticket reference (e.g., ServiceNow INC/CHG).
   - Enforce mandatory Multi-Factor Authentication (MFA) step-up.
   - Optional: Require approval from designated Authorizers prior to token minting.
3. **Automated Expiration**:
   - The Entra token expires automatically after the allocated window. Subsequent API or portal requests revert to unprivileged scope.

---

## 3. AWS IAM: Modern Temporary Credential Architecture vs Access Keys

In modern cloud PAM architectures:
1. **Antipattern (Legacy / High Risk)**: Long-lived IAM user access key pairs (`AKIA...`) embedded in developer laptops or configuration files.
2. **Best Practice (Zero Standing Privilege)**:
   - Deploy IAM Roles with minimal JSON policies (such as [`aws-least-privilege-s3.json`](file:///vault/policies/aws-least-privilege-s3.json)).
   - Require users to authenticate via AWS IAM Identity Center (formerly AWS SSO) or assume a role using `sts:AssumeRole`.
   - The AWS Security Token Service issues temporary credentials (valid 15 minutes to 1 hour) with automatic expiration:
     ```bash
     aws sts assume-role --role-arn "arn:aws:iam::123456789012:role/PAMBackupAdmin" --role-session-name "AliceSession"
     ```
   - All role assumptions and subsequent S3 API calls (`GetObject`, `ListBucket`) are immutably logged to **AWS CloudTrail Event History**.

