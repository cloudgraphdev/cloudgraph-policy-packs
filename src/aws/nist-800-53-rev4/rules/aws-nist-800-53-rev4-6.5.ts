export default {
  id: 'aws-nist-800-53-rev4-6.5',  
  title: 'AWS NIST 6.5 CloudTrail trails should be configured to log data events for S3 buckets',
  
  description: 'Data events provide visibility into the resource operations performed on or within a resource, including S3 object-level API activity. By default, trails do not log data events. The AWS API call history produced by CloudTrail enables security analysis, resource change tracking, and compliance auditing.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  You can edit an existing trail to add logging data events, but as a best practice, AWS recommends creating a separate trail specifically for logging data events.
  
  To modify an existing trail:
  
  - Navigate to CloudTrail.
  - In the left pane, select Trails.
  - Select the noncompliant trail.
  - Under Data Events, select Configure.
  - In the S3 tab, select all S3 buckets in your account and ensure Read and Write are selected.
  - Select Save.
  
  **AWS CLI**
  
  To configure a trail to log data events for all S3 buckets, replace TRAILNAME with your trail name:
  
      aws cloudtrail put-event-selectors --trail-name TRAILNAME --event-selectors '[{ "ReadWriteType": "All", "IncludeManagementEvents":true, "DataResources": [{ "Type": "AWS::S3::Object", "Values": ["arn:aws:s3"] }] }]'`,
  
  references: [
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html'
  ],  
  gql: `{
    queryawsCloudtrail { 
      id
      arn
      accountId
      __typename
      eventSelectors {
        includeManagementEvents
        readWriteType
        dataResources {
          type
        }
      }
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'medium',
  conditions: {  
    path: '@.eventSelectors',
    array_any: {
      and: [
        {
          path: '[*].includeManagementEvents',
          equal: true,
        },
        { 
          path: '[*].readWriteType', 
          equal: 'All',
        },
        {
          path: '[*].dataResources',
          array_any: {
            path: '[*].type',
            equal: 'AWS::S3::Object',
          },
        },
      ],
    },
  },
}
