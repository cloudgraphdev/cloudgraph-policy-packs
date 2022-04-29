// AWS CIS 1.2.0 Rule equivalent 1.1
export default {
  id: 'aws-nist-800-53-rev4-15.4',  
  title: 'AWS NIST 15.4 IAM root user should not be used',
  
  description: 'The "root" account has unrestricted access to all resources in the AWS account. It is highly recommended that the use of this account be avoided.',
  
  audit: `Implement the *Ensure a log metric filter and alarm exist for usage of "root" account* recommendation in the *Monitoring* section of this benchmark to receive notifications of root account usage. Additionally, executing the following commands will provide ad-hoc means for determining the last time the root account was used:
  
      aws iam generate-credential-report
  
  <br/>
  
      aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,5,11,16 | grep -B1 '<root_account>'
  
  Note: there are a few conditions under which the use of the root account is required, such as requesting a penetration test or creating a CloudFront private key.`,
  
  rationale: 'The "root" account is the most privileged AWS account. Minimizing the use of this account and adopting the principle of least privilege for access management will reduce the risk of accidental changes and unintended disclosure of highly privileged credentials.',
  
  remediation: `**Console Remediation Steps**
  
  AWS recommends that users do not use the root user for everyday tasks (even administrative ones). It is a best practice to only use the root user to create your first individual user or conduct tasks that require root.
  
  You can optionally [delete the root user’s access key or mark it as inactive.](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_delete-key)
  
  To delete the root user’s access key:
  
  - Logged in as the root user, navigate to [IAM](https://console.aws.amazon.com/iam/home).
  - From the top navigation, select your account name > My Security Credentials.
  - If you see a warning about accessing the security credentials for your AWS account, choose Continue to Security Credentials.
  - Expand Access keys (access key ID and secret access key).
  - For any active access keys, select Make Inactive and Click Delete. A confirmation modal displays. Click Delete.
  
  To make the root user’s access key inactive:
  
  - Logged in as the root user, navigate to [IAM](https://console.aws.amazon.com/iam/home).
  - From the top navigation, select your account name > My Security Credentials.
  - If you see a warning about accessing the security credentials for your AWS account, choose Continue to Security Credentials.
  - Expand Access keys (access key ID and secret access key).
  - For any active access keys, select Make Inactive.
  
  **CLI Remediation Steps**
  
  AWS recommends that users do not use the root user for everyday tasks (even administrative ones). It is a best practice to only use the root user to create your first individual user or conduct tasks that require root.
  
  You can optionally delete the root user’s access key or mark it as inactive.
  
  To delete the root user’s access key:
  
      aws iam delete-access-key --access-key-id <access key id> --user-name <username>
  
  To make the root user’s access key inactive:
  
      aws iam update-access-key --access-key-id <access key id> --status Inactive --user-name <username>`,
  
  references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
      'https://docs.aws.amazon.com/general/latest/gr/aws_tasks-that-require-root.html',
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html',
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_delete-key',
  ],
  gql: `{
    queryawsIamUser(filter: { name: { eq: "root" } }) {
      id
      arn
      accountId
        __typename
      passwordLastUsed
      passwordEnabled
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'high',
  conditions: {
    not: {
      and: [
        {
          path: '@.passwordEnabled',
          equal: true,
        },
        {
          value: { daysAgo: {}, path: '@.passwordLastUsed' },
          lessThanInclusive: 30,
        },
      ],
    },
  },
}
