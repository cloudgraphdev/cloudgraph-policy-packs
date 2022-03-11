// AWS CIS 1.2.0 Rule equivalent 1.14
export default {
  id: 'aws-pci-dss-3.2.1-iam-check-4',
  title: 'IAM Check 4: Hardware MFA should be enabled for the root user',
  description: `This control checks whether your AWS account is enabled to use multi-factor authentication (MFA) hardware device to sign in with root user credentials.

  It does not check whether you are using virtual MFA.

  To address PCI DSS requirement 8.3.1, you can choose between hardware MFA (this control) or virtual MFA ([\[PCI.IAM.5\] Virtual MFA should be enabled for the root user](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-iam-5)).

  Both time-based one-time password (TOTP) and Universal 2nd Factor (U2F) tokens are viable as hardware MFA options.`,
  rationale: `This control is related to the following PCI DSS requirements:

  **PCI DSS 8.3.1: Incorporate multi-factor authentication for all non-console access into the cardholder data environment (CDE) for personnel with administrative access.**

  The root user is the most privileged user in an account.

  MFA adds an extra layer of protection on top of a user name and password. If users with administrative privileges are accessing the cardholder data environment over a network interface rather than via a direct, physical connection to the system component, and are not physically in front of the machine they are administering, MFA is required.

  Enabling hardware MFA is a method used to incorporate multi-factor authentication (MFA) for all nonconsole administrative access`,
  remediation: `**To enable hardware-based MFA for the root account**

  1. Log in to your account using the root user credentials.
  2. Choose the account name at the top right of the page and then choose **My Security Credentials**.
  3. In the warning, choose **Continue to Security Credentials**.
  4. Choose **Multi-factor authentication (MFA)**.
  5. Choose **Activate MFA**.
  6. Choose a hardware-based (not virtual) device to use for MFA and then choose **Continue**.
  7. Complete the steps to configure the device type appropriate to your selection.`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-iam-5',
  ],
  gql: `{
    queryawsIamUser(filter: { name: { eq: "root" } }) {
      id
      arn
      accountId
       __typename
      name
      mfaActive
      virtualMfaDevices {
        serialNumber
      }
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'high',
  conditions: {
    and: [
      {
        path: '@.mfaActive',
        equal: true,
      },
      {
        jq: '[select("arn:aws:iam::" + .accountId + ":mfa/root-account-mfa-device" == .virtualMfaDevices[].serialNumber)] | { "match" : (length > 0) }',
        path: '@',
        and: [
          {
            path: '@.match',
            notEqual: true,
          },
        ],
      },
    ],
  },
}
