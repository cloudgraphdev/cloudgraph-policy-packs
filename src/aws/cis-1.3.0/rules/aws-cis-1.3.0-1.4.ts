// AWS CIS 1.2.0 Rule equivalent 1.12
export default {
  id: 'aws-cis-1.3.0-1.4',
  title: 'AWS CIS 1.4 Ensure no root account access key exists',
  description: `The root account is the most privileged user in an AWS account. AWS Access Keys provide
  programmatic access to a given AWS account. It is recommended that all access keys
  associated with the root account be removed.`,
  audit: `Perform the following to determine if the root account has access keys:
  Via the AWS Console

  1. Login to the AWS Management Console
  2. Click *Services*
  3. Click *IAM*
  4. Click on *Credential Report*
  5. This will download an *.xls* file that contains credential usage for all IAM users within an AWS Account - open this file
  6. For the *<root_account>* user, ensure the *access_key_1_active* and *access_key_2_active* fields are set to *FALSE*.

  Via CLI

  1. Run the following commands:

    aws iam generate-credential-report
    aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,9,14 | grep -B1 '<root_account>'

  2. For the *<root_account>* user, ensure the *access_key_1_active* and *access_key_2_active* fields are set to *FALSE*.`,
  rationale:
    'Removing access keys associated with the root account limits vectors by which the account can be compromised. Additionally, removing the root access keys encourages the creation and use of role-based accounts that are least privileged.',
  remediation: `Perform the following to delete or disable active root access keys being
  Via the AWS Console

  1. Sign in to the AWS Management Console as Root and open the IAM console at https://console.aws.amazon.com/iam/.
  2. Click on *<Root_Account_Name>* at the top right and select *Security Credentials* from the drop-down list
  3. On the pop-out screen Click on *Continue to Security Credentials*
  4. Click on *Access Keys* *(Access Key ID and Secret Access Key)*
  5. Under the *Status* column if there are any Keys that are Active
      1. Click on *Make Inactive* - (Temporarily disable Key - may be needed again)
      2. Click *Delete* - (Deleted keys cannot be recovered)`,
  references: [
    'http://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html',
    'http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html',
    'http://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html',
    'CCE-78910-7',
    'CIS CSC v6.0 #5.1',
  ],
  gql: `{
    queryawsIamUser(filter: { name: { eq: "root" } }) {
      id
      arn
      accountId
       __typename
      accessKeysActive
    }
  }`,
  exclude: { not: { path: '@.name', equal: 'root' } },
  resource: 'queryawsIamUser[*]',
  severity: 'high',
  conditions: {
    path: '@.accessKeysActive',
    equal: false,
  },
}
