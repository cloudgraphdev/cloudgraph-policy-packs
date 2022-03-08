// AWS CIS 1.2.0 Rule equivalent 1.2
export default {
  id: 'aws-pci-dss-3.2.1-iam-check-6',
  title:
    'IAM Check 6: MFA should be enabled for all IAM users',
  description: `This control checks whether the IAM users have multi-factor authentication (MFA) enabled.`,
  rationale: `This control is related to the following PCI DSS requirements:

  **PCI DSS 8.3.1: Incorporate multi-factor authentication for all non-console access into the cardholder data environment (CDE) for personnel with administrative access.**

  Enabling MFA for all IAM users is a method used to incorporate multi-factor authentication (MFA) for all nonconsole administrative access.
  `,
  remediation: `**To configure MFA for a user**

  1. Open the IAM console at https://console.aws.amazon.com/iam/.
  2. Choose Users.
  3. Choose the user name of the user to configure MFA for.
  4. Choose Security credentials and then choose Manage next to Assigned MFA device.
  5. Follow the Manage MFA Device wizard to assign the type of device appropriate for your environment.

  To learn how to delegate MFA setup to users, the AWS Security Blog post [How to Delegate Management of Multi-Factor Authentication to AWS IAM Users](http://aws.amazon.com/blogs/security/how-to-delegate-management-of-multi-factor-authentication-to-aws-iam-users/).`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'http://aws.amazon.com/blogs/security/how-to-delegate-management-of-multi-factor-authentication-to-aws-iam-users/'
  ],
  gql: `{
    queryawsIamUser {
      id
      arn
      accountId
       __typename
      passwordEnabled
      mfaActive
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'medium',
  conditions: {
    or: [
      {
        path: '@.passwordEnabled',
        equal: false,
      },
      {
        path: '@.mfaActive',
        equal: true,
      }
    ]
  },
}
