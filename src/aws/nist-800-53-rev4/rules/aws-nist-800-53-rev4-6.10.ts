// AWS CIS 1.2.0 Rule equivalent 2.6
export default {
  id: 'aws-nist-800-53-rev4-6.10',  
  title: 'AWS NIST 6.10 S3 bucket access logging should be enabled',
  
  description: 'Enabling server access logging provides detailed records for the requests that are made to a S3 bucket. This information is useful for security and compliance auditing purposes.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [S3](https://console.aws.amazon.com/s3/).
  - In the Bucket name list, choose the name of the bucket that you want to enable server access logging for.
  - Choose Properties.
  - Choose Server access logging.
  - Choose Enable Logging. For Target, choose the name of the bucket that you want to receive the log record objects. The target bucket must be in the same region as the source bucket and must not have a default retention period configuration.
      - (Optional) For Target prefix, type a key name prefix for log objects, so that all of the log object names begin with the same string.
  - Choose Save.
  
  **AWS CLI**
  
  To enable server access logging for an S3 bucket, first grant S3 permission. Replace MY_BUCKET_NAME with the bucket name:
  
      aws s3api put-bucket-acl --bucket MY_BUCKET_NAME --grant-write URI=http://acs.amazonaws.com/groups/s3/LogDelivery --grant-read-acp URI=http://acs.amazonaws.com/groups/s3/LogDelivery
  
  Then apply the logging policy. You’ll need to provide a JSON document with the policy; see below. Replace MY_BUCKET_NAME with the bucket name:
  
      aws s3api put-bucket-logging --bucket MY_BUCKET_NAME --bucket-logging-status file://logging.json
  
  logging.json is a JSON document containing the logging policy. The example below allows the AWS user associated with my_email@example.com to have full control over the log files. Replace MY_BUCKET_NAME, MY_PREFIX/, and my_email@example.com with the desired bucket name, log object key prefix, and email address:
  
      {
          "LoggingEnabled": {
              "TargetBucket": "MY_BUCKET_NAME",
              "TargetPrefix": "MY_PREFIX/",
              "TargetGrants": [
                  {
                      "Grantee": {
                      "Type": "AmazonCustomerByEmail",
                      "EmailAddress": "my_email@example.com"
                      },
                      "Permission": "FULL_CONTROL"
                  }
              ]
          }
      }`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html',
      'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/server-access-logging.html',
      'https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-acl.html',
      'https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-logging.html',
  ],
  gql: `{
    queryawsS3 {
      id
      arn
      accountId
       __typename
      logging
    }
  }`,
  resource: 'queryawsS3[*]',
  severity: 'medium',
  conditions: {
    path: '@.logging',
    equal: 'Enabled',
  },
}
