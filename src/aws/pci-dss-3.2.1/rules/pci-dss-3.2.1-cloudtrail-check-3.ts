export default {
  id: 'aws-pci-dss-3.2.1-cloudtrail-check-3',
  title:
    'CloudTrail Check 3: CloudTrail log file validation should be enabled ',
  description: `This control checks whether CloudTrail log file validation is enabled.

  It does not check when configurations are altered.

  To monitor and alert on log file changes, you can use Amazon EventBridge or CloudWatch metric filters.`,
  rationale: `**PCI DSS 10.5.2: Protect audit trail files from unauthorized modifications.**
  CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to Amazon S3.

  You can use these digest files to determine whether a log file was changed, deleted, or unchanged after CloudTrail delivered the log.

  This is a method that helps to protect audit trail files from unauthorized modifications.

  **PCI DSS 10.5.5: Use file-integrity monitoring or change-detection software on logs to ensure that existing log data cannot be changed without generating alerts.**
  CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to Amazon S3.

  You can use these digest files to determine whether a log file was changed, deleted, or unchanged after CloudTrail delivered the log.

  This is a method that helps to ensure file-integrity monitoring or change-detection software is used on logs.`,
  remediaton: `**To enable CloudTrail log file validation**

  1. Open the CloudTrail console at https://console.aws.amazon.com/cloudtrail/.

  2. Choose **Trails**.

  3. In the **Name** column, choose the name of a trail to edit.

  4. Under **General details**, choose **Edit**.

  5. Under **Additional settings**, for **Log file validation**, select **Enabled**.

  6. Choose **Save**.`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
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
  severity: 'low',
  conditions: {
      path: '@.logFileValidationEnabled',
      equal: 'Yes',
  },
}
