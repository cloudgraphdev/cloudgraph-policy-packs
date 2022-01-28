export default {
  id: 'aws-cis-1.2.0-1.12',
  description:
    'AWS CIS 1.12  Ensure no root account access key exists (Scored)',
  audit: `Perform the following to determine if the root account has access keys:
  Via the AWS Console
  
  1. Login to the AWS Management Console
  2. Click Services
  3. Click IAM
  4. Click on Credential Report
  5. This will download an .xls file that contains credential usage for all IAM users within an AWS Account - open this file
  6. For the <root_account> user, ensure the access_key_1_active and access_key_2_active fields are set to FALSE.
  
  Via CLI
  
  1. Run the following commands:
  
  aws iam generate-credential-report
  aws iam get-credential-report --query 'Content' --output text | base64 -d |cut -d, -f1,9,14 | grep -B1 '<root_account>'
  
  2. For the <root_account> user, ensure the access_key_1_active and access_key_2_active fields are set to FALSE.`,
  rationale: `Removing access keys associated with the root account limits vectors by which the account can be compromised. Additionally, removing the root access keys encourages the creation and use of role-based accounts that are least privileged.`,
  remediation: `Perform the following to delete or disable active root access keys being
  Via the AWS Console
  
  1. Sign in to the AWS Management Console as Root and open the IAM console at https://console.aws.amazon.com/iam/.
  2. Click on _<Root_Account_Name>_ at the top right and select Security Credentials from the drop-down list
  3. On the pop-out screen Click on Continue to Security Credentials
  4. Click on Access Keys _(Access Key ID and Secret Access Key)_
  5. Under the Status column if there are any Keys that are Active
      1. Click on Make Inactive - (Temporarily disable Key - may be needed again)
      2. Click Delete - (Deleted keys cannot be recovered)`,
  references: [
    `http://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html`,
    `http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html`,
    `http://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html`,
    `CCE- 78910 - 7`,
    `CIS CSC v6.0 #5.1`,
  ],
  gql: `{
    queryawsIamUser(filter: { name: { eq: "root" } }) {
      id
      __typename
      accessKeysActive
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'high',
  conditions: {
    path: '@.accessKeysActive',
    equal: false,
  },
}
