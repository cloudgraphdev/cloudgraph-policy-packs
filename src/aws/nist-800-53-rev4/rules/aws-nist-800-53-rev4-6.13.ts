export default {
  id: 'aws-nist-800-53-rev4-6.13',  
  title: 'AWS NIST 6.13 S3 bucket object-level logging for write events should be enabled',
  
  description: 'Object-level S3 events (GetObject, DeleteObject, and PutObject) are not logged by default, though this is recommended from a security best practices perspective for buckets that contain sensitive data.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [S3](https://console.aws.amazon.com/s3/).
  - Select the S3 Bucket and click Properties.
  - In AWS CloudTrail data events, click Configure in CloudTrail. Create a new CloudTrail trail if one doesn’t exist. For information about how to create trails in the CloudTrail console, see [Creating a Trail with the Console](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail-by-using-the-console.html).
  
    - If creating a trail: Check the Data events box. Under Data event: S3, check the Write checkbox.
    - If editing a trail: Under Data event: S3, select Edit and check the Write checkbox
    
  **AWS CLI**
  
  To enable S3 bucket object-level logging:
  
      aws cloudtrail put-event-selectors --region <region-name> --trail-name <trail-name> --event-selectors '[{ "ReadWriteType": "WriteOnly", "IncludeManagementEvents":true, "DataResources": [{ "Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::<s3-bucket-name>/"] }] }]'`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/enable-cloudtrail-events.html',
      'https://docs.aws.amazon.com/AmazonS3/latest/dev/cloudtrail-logging.html',
      'https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/put-event-selectors.html',
  ],  
  gql: `{
    queryawsAccount { 
      id
      __typename
      cloudtrail {
        eventSelectors {
          readWriteType
          dataResources {
            type
          }
        }
      }
    }
  }`,
  resource: 'queryawsAccount[*]',
  severity: 'low',
  conditions: {  
    path: '@.cloudtrail',
    array_any: {
      path: '[*].eventSelectors',
      array_any: {
        and: [
          {
            path: '[*].includeManagementEvents',
            equal: true,
          },
          { 
            path: '[*].readWriteType', 
            in: ['WriteOnly', 'All'],
          },
          {
            not: {
              path: '[*].dataResources',
              isEmpty: true,
            }
          },
        ],
      },
    }
  },
}
