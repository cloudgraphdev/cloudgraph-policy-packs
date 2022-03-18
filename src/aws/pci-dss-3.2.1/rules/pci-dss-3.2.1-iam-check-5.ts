// AWS CIS 1.2.0 Rule equivalent 1.13
export default {
  id: 'aws-pci-dss-3.2.1-iam-check-5',
  title: 'IAM Check 5: Virtual MFA should be enabled for the root user',
  description: `This control checks whether users of your AWS account require a multi-factor authentication (MFA) device to sign in with root user credentials.

  It does not check whether you are using hardware MFA.

  To address PCI DSS requirement 8.3.1, you can choose between virtual MFA (this control) or hardware MFA ([/[PCI.IAM.4/] Hardware MFA should be enabled for the root user](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-iam-4)).
  `,
  rationale: `This control is related to the following PCI DSS requirements:

  **PCI DSS 8.3.1: Incorporate multi-factor authentication for all non-console access into the cardholder data environment (CDE) for personnel with administrative access.**

  The root user is the most privileged user in an account.

  MFA adds an extra layer of protection on top of a user name and password. If users with administrative privileges are accessing the cardholder data environment, and are not physically in front of the machine they are administering, MFA is required.

  Enabling virtual MFA is a method used to incorporate multi-factor authentication (MFA) for all nonconsole administrative access.`,
  remediation: `**To enable MFA for the root account**

  1. Log in to your account using the root user credentials.
  2. Choose the account name at the top-right of the page and then choose **My Security Credentials**.
  3. In the warning, choose **Continue to Security Credentials**.
  4. Choose **Multi-factor authentication (MFA)**.
  5. Choose **Activate MFA**.
  6. Choose the type of device to use for MFA and then choose **Continue**.
  7. Complete the steps to configure the device type appropriate to your selection.`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-iam-4',
  ],
  gql: `{
    queryawsIamUser(filter: { name: { eq: "root" } }) {
      id
      arn
      accountId
       __typename
      name
      mfaActive
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'high',
  conditions: {
    path: '@.mfaActive',
    equal: true,
  },
}
