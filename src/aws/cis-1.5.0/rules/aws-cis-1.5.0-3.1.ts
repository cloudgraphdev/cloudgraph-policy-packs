// AWS CIS 1.4.0 Rule equivalent 3.1
export default {
  id: 'aws-cis-1.5.0-3.1',
  title: 'AWS CIS 3.1 Ensure CloudTrail is enabled in all regions',
  description: `AWS CloudTrail is a web service that records AWS API calls for your account and delivers
  log files to you. The recorded information includes the identity of the API caller, the time of
  the API call, the source IP address of the API caller, the request parameters, and the
  response elements returned by the AWS service. CloudTrail provides a history of AWS API
  calls for an account, including API calls made via the Management Console, SDKs, command
  line tools, and higher-level AWS services (such as CloudFormation).`,
  audit: `Perform the following to determine if CloudTrail is enabled for all regions:
  Via the management Console

  1. Sign in to the AWS Management Console and open the CloudTrail console at https://console.aws.amazon.com/cloudtrail
  2. Click on *Trails* on the left navigation pane

  - You will be presented with a list of trails across all regions

  3. Ensure at least one Trail has *All* specified in the *Region* column
  4. Click on a trail via the link in the *Name* column
  5. Ensure *Logging* is set to *ON*
  6. Ensure *Apply trail to all regions* is set to *Yes*
  7. In section *Management Events* ensure *Read/Write Events* set to *ALL*

  Via CLI

    aws cloudtrail describe-trails

  Ensure *IsMultiRegionTrail* is set to *true*

    aws cloudtrail get-trail-status --name <trailname shown in describe-trails>

  Ensure *IsLogging* is set to *true*

    aws cloudtrail get-event-selectors --trail-name <trailname shown in describe-trails>

  Ensure there is at least one Event Selector for a Trail with *IncludeManagementEvents* set to *true* and *ReadWriteType* set to *All*`,
  rationale: `The AWS API call history produced by CloudTrail enables security analysis, resource change tracking, and compliance auditing. Additionally,

  - ensuring that a multi-regions trail exists will ensure that unexpected activity occurring in otherwise unused regions is detected
  - ensuring that a multi-regions trail exists will ensure that Global Service Logging is enabled for a trail by default to capture recording of events generated on AWS global services
  - for a multi-regions trail, ensuring that management events configured for all type of Read/Writes ensures recording of management operations that are performed on all resources in an AWS account`,
  remediation: `Perform the following to enable global (Multi-region) CloudTrail logging:
  Via the management Console

  1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/cloudtrail
  2. Click on *Trails* on the left navigation pane
  3. Click *Get Started Now*, if presented


  - Click *Add new trail*
  - Enter a trail name in the *Trail* name box
  - Set the *Apply trail to all regions* option to Yes
  - Specify an S3 bucket name in the *S3 bucket* box
  - Click *Create*

  4. If 1 or more trails already exist, select the target trail to enable for global logging
  5. Click the edit icon (pencil) next to *Apply trail to all regions* , Click *Yes* and Click *Save*.
  6. Click the edit icon (pencil) next to *Management Events* click All for setting Read/Write Events and Click *Save*.

  Via CLI

    aws cloudtrail create-trail --name <trail_name> --bucket-name <s3_bucket_for_cloudtrail> --is-multi-region-trail
    aws cloudtrail update-trail --name <trail_name> --is-multi-region-trail

  Note: Creating CloudTrail via CLI without providing any overriding options configures *Management Events* to set *All* type of *Read/Writes* by default.`,
  references: [
    'CCE-78913-1',
    'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-management-events',
    'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-and-data-events-with-cloudtrail.html?icmpid=docs_cloudtrail_console#logging-management-events',
    'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-supported-services.html#cloud-trail-supported-services-data-events',
  ],
  gql: `{
    queryawsAccount { 
      id
      __typename
      cloudtrail {
        isMultiRegionTrail
        status {
          isLogging
        }
        eventSelectors {
          readWriteType
          includeManagementEvents
        }
      }
    }
  }`,
  resource: 'queryawsAccount[*]',
  severity: 'medium',
  conditions: {
    path: '@.cloudtrail',
    array_any: {
      and: [
        {
          path: '[*].isMultiRegionTrail',
          equal: 'Yes',
        },
        {
          path: '[*].status.isLogging',
          equal: true,
        },
        {
          path: '[*].eventSelectors',
          array_any: {
            and: [
              { path: '[*].readWriteType', equal: 'All' },
              {
                path: '[*].includeManagementEvents',
                equal: true,
              },
            ],
          },
        },
      ],
    },
  },
}
