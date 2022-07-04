export default {
  id: 'aws-cis-1.4.0-1.7',
  title:
    "AWS CIS 1.7 Eliminate use of the 'root' user for administrative and daily tasks",

  description:
    "With the creation of an AWS account, a 'root user' is created that cannot be disabled or deleted. That user has unrestricted access to and control over all resources in the AWS account. It is highly recommended that the use of this account be avoided for everyday tasks.",

  audit: `**From Console:**

  1. Login to the AWS Management Console at https://console.aws.amazon.com/iam/
  2. In the left pane, click *Credential Report*
  3. Click on *Download Report*
  4. Open of Save the file locally
  5. Locate the *<root account>* under the user column
  6. Review *password_last_used*, *access_key_1_last_used_date*, *access_key_2_last_used_date* to determine when the 'root user' was last used.

  **From Command Line:**
  Run the following CLI commands to provide a credential report for determining the last time the 'root user' was used:

      aws iam generate-credential-report

      aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,5,11,16 | grep -B1 '<root_account>'

  Review *password_last_used*, *access_key_1_last_used_date*, *access_key_2_last_used_date* to determine when the root user was last used.

  **Note:** There are a few conditions under which the use of the 'root' user account is required. Please see the reference links for all of the tasks that require use of the 'root' user.`,

  rationale:
    "The 'root user' has unrestricted access to and control over all account resources. Use of it is inconsistent with the principles of least privilege and separation of duties, and can lead to unnecessary harm due to error or account compromise.",

  remediation: `Remediation:

  If you find that the 'root' user account is being used for daily activity to include administrative tasks that do not require the 'root' user:

  1. Change the 'root' user password.
  2. Deactivate or delete any access keys associate with the 'root' user.

  **Remember, anyone who has 'root' user credentials for your AWS account has unrestricted access to and control of all the resources in your account, including billing information.`,

  references: [
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html',
    'https://docs.aws.amazon.com/general/latest/gr/aws_tasks-that-require-root.html',
  ],
  gql: `{
    queryawsIamUser(filter: { name: { eq: "root" } }) {
      id
      arn
      accountId
       __typename
      passwordLastUsed
      passwordEnabled
      accessKeysActive
      accessKeyData {
        lastUsedDate
        status
      }
    }
  }`,
  exclude: { not: { path: '@.name', equal: 'root' } },
  resource: 'queryawsIamUser[*]',
  severity: 'high',
  conditions: {
    not: {
      or: [
        {
          and: [
            {
              path: '@.passwordEnabled',
              equal: true,
            },
            {
              value: { daysAgo: {}, path: '@.passwordLastUsed' },
              lessThanInclusive: 90,
            },
          ],
        },
        {
          and: [
            {
              path: '@.accessKeysActive',
              equal: true,
            },
            {
              path: '@.accessKeyData',
              array_any: {
                and: [
                  {
                    path: '[*].status',
                    equal: 'Active',
                  },
                  {
                    value: { daysAgo: {}, path: '[*].lastUsedDate' },
                    lessThanInclusive: 90,
                  },
                ],
              },
            },
          ],
        },
      ],
    },
  },
}
