// AWS CIS 1.2.0 Rule equivalent 2.5
export default {
  id: 'aws-pci-dss-3.2.1-config-check-1',
  title:
    'Config Check 1: AWS Config should be enabled',
  description: `This control checks whether AWS Config is enabled in the account for the local Region and is recording all resources.

  It does not check for change detection for all critical system files and content files, as AWS Config supports only a subset of resource types.

  The AWS Config service performs configuration management of supported AWS resources in your account and delivers log files to you. The recorded information includes the configuration item (AWS resource), relationships between configuration items, and any configuration changes between resources.

  Security Hub recommends that you enable AWS Config in all Regions. The AWS configuration item history that AWS Config captures enables security analysis, resource change tracking, and compliance auditing.`,
  rationale: `This control is related to the following PCI DSS requirements:

  **PCI DSS 10.5.2: Protect audit trail files from unauthorized modifications.**

  AWS Config continuously monitors, tracks, and evaluates your AWS resource configurations for desired settings and generates configuration change history files every six hours.

  You should enable AWS Config to protect audit trail files from unauthorized modifications.

  **PCI DSS 11.5: Deploy a change-detection mechanism to alert personnel to unauthorized modification of critical system files, configuration files, or content files; and configure the software to perform critical file comparisons at least weekly.**

  AWS Config continuously monitors, tracks, and evaluates your AWS resource configurations for desired settings and generates configuration change history files every six hours.

  You should enable AWS Config to ensure a change-detection mechanism is deployed and is configured to perform critical file comparisons at least weekly.`,
  remediation: `**To configure AWS Config settings**

  1. Open the AWS Config console at https://console.aws.amazon.com/config/
  2. Choose the Region to configure AWS Config in.
  3. If you have not used AWS Config before, choose **Get started**.
  4. On the **Settings** page, do the following:

     a. Under **Resource types to record**, choose **Record all resources supported in this region** and **Include global resources (e.g., AWS IAM resources)**.

     b. Under **Amazon S3 bucket**, either specify the bucket to use or create a bucket and optionally include a prefix.

     c. Under **Amazon SNS topic**, either select an Amazon SNS topic from your account or create one. For more information about Amazon SNS, see the [Amazon Simple Notification Service Getting Started Guide](https://docs.aws.amazon.com/sns/latest/dg/sns-getting-started.html).

     d. Under AWS **Config role**, either choose **Create AWS Config service-linked role** or choose **Choose a role from your account** and then choose the role to use.

  5. Choose **Next**.
  6. On the **AWS Config rules** page, choose **Skip**.
  7. Choose **Confirm**.

  For more information about using AWS Config from the AWS CLI, see the [AWS Config Developer Guide](https://docs.aws.amazon.com/config/latest/developerguide/gs-cli-subscribe.html).

  You can also use an AWS CloudFormation template to automate this process. For more information, see the [AWS CloudFormation User Guide](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-sampletemplates.html).
  `,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/sns/latest/dg/sns-getting-started.html',
    'https://docs.aws.amazon.com/config/latest/developerguide/gs-cli-subscribe.html',
    'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-sampletemplates.html'
  ],
  gql: `{
    queryawsAccount {
      id
      __typename
      configurationRecorders {
        recordingGroup {
          allSupported
          includeGlobalResourceTypes
        }
        status {
          recording
          lastStatus
        }
      }
    }
  }`,
  resource: 'queryawsAccount[*]',
  severity: 'medium',
  conditions: {
    path: '@.configurationRecorders',
    array_any: {
      and: [
        {
          path: '[*].recordingGroup.allSupported',
          equal: true,
        },
        {
          path: '[*].recordingGroup.includeGlobalResourceTypes',
          equal: true,
        },
        {
          path: '[*].status.recording',
          equal: true,
        },
        {
          path: '[*].status.lastStatus',
          equal: 'SUCCESS',
        },
      ],
    },
  },
}
