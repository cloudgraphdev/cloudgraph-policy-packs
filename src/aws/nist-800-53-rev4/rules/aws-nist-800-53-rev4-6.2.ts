// AWS CIS 1.2.0 Rule equivalent 2.2
export default {
  id: 'aws-nist-800-53-rev4-6.2',  
  title: 'AWS NIST 6.2 CloudTrail log file validation should be enabled',
  
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
  rationale: 'Enabling log file validation will provide additional integrity checking of CloudTrail logs.',
  
  remediation: `**AWS Console**
  
  - Navigate to [CloudTrail](https://console.aws.amazon.com/cloudtrail/).
  - In the left navigation, click Trails.
  - Click the target trail.
  - Within General details, click Edit.
  - Scroll down to Additional settings, and enable Log file validation.
  - Click Save changes.
  
  **AWS CLI**
  
  Get a list of all CloudTrail trails and view their configuration:
  
      aws cloudtrail describe-trails
  
  Update any trail that has “LogFileVaidationEnabled” set to false:
  
      aws cloudtrail update-trail --name <trail_name> --enable-log-file-validation`,
  
  references: [
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html',
      'https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/update-trail.html'
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
