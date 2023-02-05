export default {
  id: 'gcp-cis-1.3.0-2.14',
  title:
    'GCP CIS 2.14 Ensure \'Access Transparency\' is \'Enabled\'',
  description: 'GCP Access Transparency provides audit logs for all actions that Google personnel take in syour Google Cloud resources.',
  audit: `**Determine if Access Transparency is Enabled**

  1. From the Google Cloud Home, click on the Navigation hamburger menu in the top left. Hover over the IAM & Admin Menu. Select settings in the middle of the column that opens.
  2. The status will be under the heading *Access Transparency*. Status should be Enabled`,
  rationale: `Controlling access to your information is one of the foundations of information security.
  Given that Google Employees do have access to your organizations' projects for support
  reasons, you should have logging in place to view who, when, and why your information is
  being accessed.`,
  remediation: `**Add privileges to enable Access Transparency**

  1. From the Google Cloud Home, within the project you wish to check, click on the Navigation hamburger menu in the top left. Hover over the 'IAM and Admin'. Select IAM in the top of the column that opens.
  2. Click the blue button the says *+add* at the top of the screen.
  3. In the *principals* field, select a user or group by typing in their associated email address.
  4. Click on the *role* field to expand it. In the filter field enter *Access Transparency Admin* and select it.
  5. Click *save*.

  **Verify that the Google Cloud project is associated with a billing account**

  1. From the Google Cloud Home, click on the Navigation hamburger menu in the top left. Select *Billing*.
  2. If you see *This project is not associated with a billing account* you will need to enter billing information or switch to a project with a billing account.
  
  **Enable Access Transparency**

  1. From the Google Cloud Home, click on the Navigation hamburger menu in the top left. Hover over the IAM & Admin Menu. Select *settings* in the middle of the column that opens.
  2. Click the blue button labeled Enable *Access Transparency for Organization*

  **Default Value:**

  By default Access Transparency is not enabled.`,
  references: [
    'https://cloud.google.com/cloud-provider-access-management/accesstransparency/docs/overview',
    'https://cloud.google.com/cloud-provider-access-management/accesstransparency/docs/enable',
    'https://cloud.google.com/cloud-provider-access-management/accesstransparency/docs/reading-logs',
    'https://cloud.google.com/cloud-provider-access-management/accesstransparency/docs/reading-logs#justification_reason_codes',
    'https://cloud.google.com/cloud-provider-access-management/accesstransparency/docs/supported-services',
  ],
  severity: 'unknown',
}
