export default {
  id: 'aws-pci-dss-3.2.1-guardDuty-check-1',
  title: 'GuardDuty Check 1: GuardDuty should be enabled',
  description: `This control checks whether Amazon GuardDuty is enabled in your AWS account and Region.

  While GuardDuty can be effective against attacks that an intrusion detection system would typically protect, it might not be a complete solution for every environment. This rule also does not check for the generation of alerts to personnel. For more information about GuardDuty, see the [Amazon GuardDuty User Guide](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html).`,
  rationale: `This control is related to the following PCI DSS requirements:

  **PCI DSS 11.4 Use intrusion-detection and/or intrusion-prevention techniques to detect and/or prevent intrusions into the network.**

  GuardDuty can help to meet requirement 11.4 by monitoring traffic at the perimeter of the cardholder data environment and all critical points within it. It can also keep all intrusion-detection engines, baselines, and signatures up to date. Findings are generated from GuardDuty. You can send these alerts to personnel using Amazon CloudWatch. See [Creating custom responses to GuardDuty findings with Amazon CloudWatch Events](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_cloudwatch.html) in the _Amazon GuardDuty User Guide_. Not enabling GuardDuty in your AWS account might violate the requirement to use intrusion-detection and/or prevention techniques to prevent intrusions into the network.`,
  remediation: `To remediate this issue, you enable GuardDuty.

  For details on how to enable GuardDuty, including how to use AWS Organizations to manage multiple accounts, see [Getting started with GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html) in the _Amazon GuardDuty User Guide_.`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-guardduty-1',
    'https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html',
  ],
  gql: `{
    queryawsAccount {
      id
      regions
      __typename
      guardDutyDetectors {
        region
        status
        dataSources {
          cloudTrail {
            status
          }
          dnsLogs {
            status
          }
          flowLogs {
            status
          }
          s3Logs {
            status
          }
        }
      }
    }
  }`,
  resource: 'queryawsAccount[*]',
  severity: 'high',
  conditions: {
    and: [
      {
        path: '@.guardDutyDetectors',
        isEmpty: false,
      },
      {
        path: '@',
        jq: '[.regions[]  as $scanned |  { scannedRegion: $scanned, detectors: [.guardDutyDetectors[] | select(.region == $scanned )]  }]',
        array_all: {
          or: [
            {
              path: '[*].scannedRegion',
              // GuardDuty not supported
              in: [
                'ap-northeast-3',
                'af-south-1',
                'eu-south-1',
                'me-south-1',
                'us-gov-east-1',
                'us-gov-west-1',
                'cn-northwest-1',
                'cn-north-1',
              ],
            },
            {
              and: [
                {
                  path: '[*].detectors[0].status',
                  equal: 'ENABLED',
                },
                {
                  path: '[*].detectors[0].dataSources.cloudTrail.status',
                  notEqual: 'ENABLED',
                },
                {
                  path: '[*].detectors[0].dataSources.dnsLogs.status',
                  notEqual: 'ENABLED',
                },
                {
                  path: '[*].detectors[0].dataSources.flowLogs.status',
                  notEqual: 'ENABLED',
                },
                {
                  path: '[*].detectors[0].dataSources.s3Logs.status',
                  notEqual: 'ENABLED',
                },
              ],
            },
          ],
        },
      },
    ],
  },
}
