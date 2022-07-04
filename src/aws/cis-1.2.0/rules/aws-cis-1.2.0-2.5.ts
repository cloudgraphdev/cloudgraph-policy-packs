/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
/* eslint-disable @typescript-eslint/no-explicit-any */
export default {
  id: 'aws-cis-1.2.0-2.5',
  title: 'AWS CIS 2.5 Ensure AWS Config is enabled in all regions',
  description:
    'AWS Config is a web service that performs configuration management of supported AWS resources within your account and delivers log files to you. The recorded information includes the configuration item (AWS resource), relationships between configuration items (AWS resources), any configuration changes between resources. It is recommended to enable AWS Config be enabled in all regions.',

  audit: `Process to evaluate AWS Config configuration per region Via AWS Management Console:

  1. Sign in to the AWS Management Console and open the AWS Config console at https://console.aws.amazon.com/config/.
  2. On the top right of the console select target Region.
  3. If presented with Setup AWS Config - follow remediation procedure:
  4. On the Resource inventory page, Click on edit (the gear icon). The Set Up AWS Config page appears.
  5. Ensure 1 or both check-boxes under "All Resources" is checked.
      - Include global resources related to IAM resources - which needs to be enabled in 1 region only
  6. Ensure the correct S3 bucket has been defined.
  7. Ensure the correct SNS topic has been defined.
  8. Repeat steps 2 to 7 for each region.

  Via AWS Command Line Interface:

  1. Run this command to show all AWS Config recorders and their properties:

          aws configservice describe-configuration-recorders

  2. Evaluate the output to ensure that there's at least one recorder for which recordingGroup object includes "allSupported": true AND "includeGlobalResourceTypes": true

      Note: There is one more parameter "ResourceTypes" in recordingGroup object. We don't need to check the same as whenever we set "allSupported": true, AWS enforces resource types to be empty ("ResourceTypes":[]) Sample Output:

              {
                  "ConfigurationRecorders": [
                      {
                      "recordingGroup": {
                          "allSupported": true,
                          "resourceTypes": [],
                          "includeGlobalResourceTypes": true
                      },
                      "roleARN": "arn:aws:iam::<AWS_Account_ID>:role/service-role/<config-role-name>",
                      "name": "default"
                      }
                  ]
              }

  3. Run this command to show the status for all AWS Config recorders:

          aws configservice describe-configuration-recorder-status

  4. In the output, find recorders with name key matching the recorders that met criteria in step 2. Ensure that at least one of them includes "recording": true and "lastStatus": "SUCCESS"`,

  rationale:
    'The AWS configuration item history captured by AWS Config enables security analysis, resource change tracking, and compliance auditing.',

  remediation: `To implement AWS Config configuration:
  Via AWS Management Console:

  1. Select the region you want to focus on in the top right of the console
  2. Click Services
  3. Click Config
  4. Define which resources you want to record in the selected region
  5. Choose to include global resources (IAM resources)
  6. Specify an S3 bucket in the same account or in another managed AWS account
  7. Create an SNS Topic from the same AWS account or another managed AWS account

  Via AWS Command Line Interface:

  1. Ensure there is an appropriate S3 bucket, SNS topic, and IAM role per the [AWS Config Service prerequisites](https://docs.aws.amazon.com/config/latest/developerguide/gs-cli-prereq.html).
  2. Run this command to set up the configuration recorder

          aws configservice subscribe --s3-bucket my-config-bucket --sns-topic arn:aws:sns:us-east-1:012345678912:my-config-notice --iam-role arn:aws:iam::012345678912:role/myConfigRole

  3. Run this command to start the configuration recorder:

          start-configuration-recorder --configuration-recorder-name <value>`,

  references: [
    'CCE-78917-2',
    'CIS CSC v6.0 #1.1, #1.3, #1.4, #5.2, #11.1 - #11.3, #14.6',
    'http://docs.aws.amazon.com/cli/latest/reference/configservice/describe-configuration-recorder-status.html',
  ],
  gql: `{
    queryawsAccount { 
      id
      __typename
      regions
      configurationRecorders {
        region
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
  check: ({ resource }: any): boolean => {
    const regionsWithConfigEnabled: { [region: string]: boolean } = {}
    resource.configurationRecorders.forEach((recorder: any) => {
      if (
        recorder.recordingGroup.allSupported === true &&
        recorder.recordingGroup.includeGlobalResourceTypes === true &&
        recorder.status.recording === true &&
        recorder.status.lastStatus === 'SUCCESS'
      )
        regionsWithConfigEnabled[recorder.region] = true
    })

    return resource.regions.every(
      (region: string) => regionsWithConfigEnabled[region]
    )
  },
}
