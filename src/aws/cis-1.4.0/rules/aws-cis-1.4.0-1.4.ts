// AWS CIS 1.2.0 Rule equivalent 1.12
export default {
  id: 'aws-cis-1.4.0-1.4',
  title: "AWS CIS 1.4 Ensure no 'root' user account access key exists",

  description:
    "The 'root' user account is the most privileged user in an AWS account. AWS Access Keys provide programmatic access to a given AWS account. It is recommended that all access keys associated with the 'root' user account be removed.",

  audit: `Perform the following to determine if the 'root' user account has access keys:
  
  **From Console:**
  
  1. Login to the AWS Management Console
  2. Click *Services*
  3. Click *IAM*
  4. Click on *Credential Report*
  5. This will download an *.xls* file which contains credential usage for all IAM users within an AWS Account - open this file
  6. For the *<root_account>* user, ensure the *access_key_1_active* and *access_key_2_active* fields are set to *FALSE* .
  
  **From Command Line:**
  Run the following command:
  
      aws iam get-account-summary | grep "AccountAccessKeysPresent"
  
  If no 'root' access keys exist the output will show "AccountAccessKeysPresent": 0,. If the output shows a "1" than 'root' keys exist, refer to the remediation procedure below.`,

  rationale:
    "Removing access keys associated with the 'root' user account limits vectors by which the account can be compromised. Additionally, removing the 'root' access keys encourages the creation and use of role based accounts that are least privileged.",

  remediation: `Perform the following to delete or disable active 'root' user access keys 
  
  **From Console:**
  
  1. Sign in to the AWS Management Console as 'root' and open the IAM console at https://console.aws.amazon.com/iam/.
  2. Click on <Root_Account_Name> at the top right and select *My Security Credentials* from the drop down list
  3. On the pop out screen Click on *Continue to Security Credentials*
  4. Click on *Access Keys* *(Access Key ID and Secret Access Key)*
  5. Under the *Status* column if there are any Keys which are Active
      - Click on *Make Inactive* - (Temporarily disable Key - may be needed again)
      - Click *Delete* - (Deleted keys cannot be recovered)`,

  references: [
    'http://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html',
    'http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html',
    'http://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html',
    'CCE-78910-7',
    'https://aws.amazon.com/blogs/security/an-easier-way-to-determine-the-presence-of-aws-account-access-keys/',
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
