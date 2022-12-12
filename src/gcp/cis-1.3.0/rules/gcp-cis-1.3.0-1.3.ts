export default {
  id: 'gcp-cis-1.3.0-1.3',

  title:
    'GCP CIS 1.3 Ensure that Security Key Enforcement is enabled for all admin accounts',
  description:
    'Setup Security Key Enforcement for Google Cloud Platform admin accounts.',
  rationale:
    'Google Cloud Platform users with Organization Administrator roles have the highest level of privilege in the organization. These accounts should be protected with the strongest form of two-factor authentication: Security Key Enforcement. Ensure that admins use Security Keys to log in instead of weaker second factors like SMS or one-time passwords (OTP). Security Keys are actual physical keys used to access Google Organization Administrator Accounts. They send an encrypted signature rather than a code, ensuring that logins cannot be phished.',

  audit: `**Step 1**: Identify users with Organization Administrator privileges:

    gcloud organizations get-iam-policy ORGANIZATION_ID

  Look for members granted the role "roles/resourcemanager.organizationAdmin".

  **Step 2**: Manually verify that Security Key Enforcement has been enabled for each account.`,

  remediation: `For each Google Cloud Platform project:

  **Step 1**: Identify users with the Organization Administrator role.

  **Step 2**: Setup Security Key Enforcement for each account. Learn more at: https://cloud.google.com/security-key/`,

  references: [
    'https://cloud.google.com/security-key/',
    'https://gsuite.google.com/learn-more/key_for_working_smarter_faster_and_more_securely.html',
  ],

  severity: 'medium',
}
