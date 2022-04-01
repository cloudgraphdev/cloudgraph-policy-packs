export default {
  id: 'aws-nist-800-53-rev4-6.6',  
  title: 'AWS NIST 6.6 CloudTrail trails should be configured to log management events',
  
  description: 'Management events provide visibility into management operations that are performed on resources in your AWS account. Management events can also include non-API events that occur in your account. For example, when a user logs in to your account, CloudTrail logs the ConsoleLogin event. CloudTrail logging enables security analysis, resource change tracking, and compliance auditing.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to CloudTrail.
  - In the left pane, select Trails.
  - Select the noncompliant trail.
  - Under Management Events, select Edit.
  - Under Event type, select Management Events.
  - Under Management Events, select Read and/or Write.
  - Select Save Changes.
  
  **AWS CLI**
  
  Be aware that the command to configure logging management events will overwrite your current data event settings. Before configuring the trail, check your settings first, replacing MYTRAILNAME with your trail name:
  
      aws cloudtrail get-event-selectors --trail-name MYTRAILNAME
  
  Copy the DataResources portion of the output. It’ll look something like this: 
  
      "DataResources": [{ "Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::MYBUCKETNAME1/prefix", "arn:aws:s3:::MYBUCKETNAME2/prefix2"] }]
  
  To configure a trail to log management events (and retain your current data event settings), replace MYTRAILNAME with your trail name and change the values in DataResources to the output you copied from the previous command:
  
      aws cloudtrail put-event-selectors --trail-name MYTRAILNAME --event-selectors '[{ "ReadWriteType": "All", "IncludeManagementEvents":true, "DataResources": [{ "Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::MYBUCKETNAME1/prefix", "arn:aws:s3:::MYBUCKETNAME2/prefix2"] }] }]'`,
  
  references: [
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html#logging-management-events',
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html#logging-management-events-with-the-cloudtrail-console',
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html#creating-mgmt-event-selectors-with-the-AWS-CLI',
  ],
  gql: `{
    queryawsCloudtrail { 
      id
      arn
      accountId
      __typename
      eventSelectors {
        includeManagementEvents
      }
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'medium',
  conditions: {  
    not: {
      path: '@.eventSelectors',
      array_any: {
        path: '[*].includeManagementEvents',
        equal: false,
      },
    },
  },
}
