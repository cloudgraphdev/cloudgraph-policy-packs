export default {
  id: 'aws-nist-800-53-rev4-3.1',  
  title: 'AWS NIST 3.1 CloudTrail log files should be encrypted with customer managed KMS keys',
  
  description: 'By default, the log files delivered by CloudTrail to your bucket are encrypted with Amazon S3-managed encryption keys (SSE-S3). To get control over key rotation and obtain auditing visibility into key usage, use SSE-KMS to encrypt your log files with customer managed KMS keys',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [CloudTrail](https://console.aws.amazon.com/cloudtrail).
  - In the left navigation, select Trails.
  - Click on a Trail.
  - Under General details, click Edit.
  - In log file SSE-KMS encryption, select Enabled.
  - In Customer managed AWS KMS key, either use a new or existing key.
  - Enter the AWS KMS alias.
  - Click Save changes.
  
  **AWS CLI**
  
  Create a new KMS key to use for CloudTrail encryption. If you already have a key you wish to use, skip this step.
  
      aws kms create-key
  
  Update the KMS key policy to provide the necessary permissions.
  
      aws kms put-key-policy --key-id "<key-arn>" --policy-name default --policy '{"Version": "2012-10-17","Id": "key-default-1","Statement":[{"Sid": "Enable IAM User Permissions","Effect":"Allow","Principal": {"AWS":"arn:aws:iam::<aws-account-number>:root"},"Action":"kms:*","Resource":"*"},{"Sid":"Allow CloudTrail to encrypt logs","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"kms:GenerateDataKey*","Resource":"*","Condition":{"StringLike":{"kms:EncryptionContext:aws:cloudtrail:arn":["arn:aws:cloudtrail:*:<aws-account-number>:trail/*"]}}},{"Sid":"Enable CloudTrail log decrypt permissions","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<aws-account-number>:<role-or-user>/<role-name-or-user-name>"},"Action":"kms:Decrypt","Resource":"*","Condition":{"Null":{"kms:EncryptionContext:aws:cloudtrail:arn":"false"}}},{"Sid":"Allow CloudTrail access","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"kms:DescribeKey","Resource":"*"}]}'
  
  Update the trail configuration with the KMS key ID.
  
      aws cloudtrail update-trail --name france --kms-key-id "<key-arn>" --s3-bucket-name <bucket-name>`,
  
  references: [
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html',
      'https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html',
      'https://docs.aws.amazon.com/cli/latest/reference/kms/create-key.html',
      'https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/update-trail.html',
  ],  
  gql: `{
    queryawsCloudtrail {
      id
      arn
      accountId
       __typename
			kmsKeyId
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'high',
  conditions: {
    path: '@.kmsKeyId',
    notEqual: null,
  },
}
