export default {
  id: 'gcp-cis-1.2.0-1.2',

  title:
    'Ensure that multi-factor authentication is enabled for all non-service accounts',
  description:
    'Setup multi-factor authentication for Google Cloud Platform accounts.',
  rationale:
    'Multi-factor authentication requires more than one mechanism to authenticate a user. This secures user logins from attackers exploiting stolen or weak credentials',

  audit: `For each Google Cloud Platform project, folder, or organization:

  **Step 1** : Identify non-service accounts.

  **Step 2** : Manually verify that multi-factor authentication for each account is set.`,

  remediation: `For each Google Cloud Platform project:

  **Step 1** : Identify non-service accounts.

  **Step 2** : Setup multi-factor authentication for each account`,

  references: [
    'https://cloud.google.com/solutions/securing-gcp-account-u2f',
    'https://support.google.com/accounts/answer/185839',
  ],

  severity: 'medium',
}
