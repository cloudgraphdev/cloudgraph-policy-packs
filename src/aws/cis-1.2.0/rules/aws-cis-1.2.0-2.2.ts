export default {
  id: 'aws-cis-1.2.0-2.2',
  title: 'AWS CIS 2.2 Ensure CloudTrail log file validation is enabled',
  description: `CloudTrail log file validation creates a digitally signed digest file containing a hash of each
  log that CloudTrail writes to S3. These digest files can be used to determine whether a log
  file was changed, deleted, or unchanged after CloudTrail delivered the log. It is
  recommended that file validation be enabled on all CloudTrails.`,
  audit: `Perform the following on each trail to determine if log file validation is enabled:
  Via the management Console

  1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/cloudtrail
  2. Click on *Trails* on the left navigation pane
  3. For Every Trail:


  - Click on a trail via the link in the Name column
  - Under the *S3* section, ensure *Enable log file validation* is set to *Yes*

  Via CLI

    aws cloudtrail describe-trails

  Ensure *LogFileValidationEnabled* is set to *true* for each trail`,
  rationale: `Enabling log file validation will provide additional integrity checking of CloudTrail logs.`,
  remediation: `Perform the following to enable log file validation on a given trail:
  Via the management Console

  1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/cloudtrail
  2. Click on *Trails* on the left navigation pane
  3. Click on target trail
  4. Within the *S3* section click on the edit icon (pencil)
  5. Click *Advanced*
  6. Click on the *Yes* radio button in section *Enable log file validation*
  7. Click *Save*

  Via CLI

    aws cloudtrail update-trail --name <trail_name> --enable-log-file-validation

  Note that periodic validation of logs using these digests can be performed by running the following command:

    aws cloudtrail validate-logs --trail-arn <trail_arn> --start-time <start_time> --end-time <end_time>
`,
  references: [
    `http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html`,
    `CCE- 78914 - 9`,
    `CIS CSC v6.0 #6.3`,
  ],
  gql: `{
    queryawsCloudtrail {
      id
      arn
      accountId
       __typename
      logFileValidationEnabled
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'medium',
  conditions: {
    path: '@.logFileValidationEnabled',
    equal: 'Yes',
  },
}
