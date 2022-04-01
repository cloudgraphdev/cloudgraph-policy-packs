export default {
  id: 'aws-nist-800-53-rev4-3.2',  
  title: 'AWS NIST 3.2 CloudWatch log groups should be encrypted with customer managed KMS keys',
  
  description: 'CloudWatch log groups are encrypted by default. However, utilizing customer managed KMS keys gives you more control over key rotation and provides auditing visibility into key usage.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Sign in to the AWS Management Console and open the AWS Key Management Service (AWS KMS) console at [KMS](https://console.aws.amazon.com/kms).
  - To change the AWS Region, use the Region selector in the upper-right corner of the page.
  - In the navigation pane, choose Customer managed keys.
  - Choose Create key.
  - Type an alias for the CMK.
  - Choose Next.
  - Type in a Tag key / Tag value (Optional) and click next.
  - Select the IAM users and roles that can administer the CMK.
  - (Optional) To prevent the selected IAM users and roles from deleting this CMK, in the Key deletion section at the bottom of the page, clear the Allow key administrators to delete this key check box.
  - Choose Next.
  - Select the IAM users and roles that can use the CMK for cryptographic operations.
  - Choose Next.
  - Review the key policy document that was created from your choices. You can edit it, too.
  - Use CLI steps to [associate the KMS key with the log group](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html).
  
  **AWS CLI**
  
  Create a KMS key and allow CloudWatch logs access.
  
      aws kms create-key --policy '{"Version":"2012-10-17","Id":"key-default-1","Statement":[{"Sid":"default","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<account-number>:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Allow","Principal":{"Service":"logs.<region>.amazonaws.com"},"Action":["kms:Encrypt*","kms:Decrypt*","kms:ReEncrypt*","kms:GenerateDataKey*","kms:Describe*"],"Resource":"*"}]}'
  
  Associate the CloudWatch log group with the KMS key.
  
      aws logs associate-kms-key --log-group-name "<name>" --kms-key-id "<key-arn>"`,
  
  references: [
      'https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html#create-keys-console',
      'https://docs.aws.amazon.com/cli/latest/reference/logs/associate-kms-key.html',
      'https://docs.aws.amazon.com/cli/latest/reference/kms/create-key.html',
      'https://docs.aws.amazon.com/cli/latest/reference/logs/associate-kms-key.html',
  ],   
  gql: `{
    queryawsCloudwatchLog {
      id
      arn
      accountId
       __typename
			kmsKeyId
    }
  }`,
  resource: 'queryawsCloudwatchLog[*]',
  severity: 'medium',
  conditions: {
    path: '@.kmsKeyId',
    notEqual: null,
  },
}
