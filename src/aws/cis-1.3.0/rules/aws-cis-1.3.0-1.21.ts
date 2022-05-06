// AWS CIS 1.4.0 Rule equivalent 1.20
export default {
  id: 'aws-cis-1.3.0-1.21',  
  title: 'AWS CIS 1.21 Ensure that IAM Access analyzer is enabled',
  
  description: `Enable IAM Access analyzer for IAM policies about all resources.
  
  IAM Access Analyzer is a technology introduced at AWS reinvent 2019. After the Analyzer is enabled in IAM, scan results are displayed on the console showing the accessible resources. Scans show resources that other accounts and federated users can access, such as KMS keys and IAM roles. So the results allow you to determine if an unintended user is allowed, making it easier for administrators to monitor least privileges access.`,
  
  audit: `**From Console:**
  
  1. Open the IAM console at https://console.aws.amazon.com/iam/
  2. Choose Access analyzer
  3. Ensure that the STATUS is set to Active
  
  **From Command Line:**
  
  1. Run the following command:
  
              aws accessanalyzer get-analyzer --analyzer-name | grep status
  
  2. Ensure that the "status" is set to "ACTIVE"`,
  
  rationale: 'AWS IAM Access Analyzer helps you identify the resources in your organization and accounts, such as Amazon S3 buckets or IAM roles, that are shared with an external entity. This lets you identify unintended access to your resources and data. Access Analyzer identifies resources that are shared with external principals by using logic-based reasoning to analyze the resource-based policies in your AWS environment. IAM Access Analyzer continuously monitors all policies for S3 bucket, IAM roles, KMS(Key Management Service) keys, AWS Lambda functions, and Amazon SQS(Simple Queue Service) queues.',
  
  remediation: `**From Console:**  
  Perform the following to enable IAM Access analyzer for IAM policies:
  
  1. Open the IAM console at https://console.aws.amazon.com/iam/.
  2. Choose *Access analyzer*.
  3. Choose *Create analyzer*.
  4. On the *Create analyzer* page, confirm that the Region displayed is the *Region* where you want to enable Access Analyzer.
  5. Enter a name for the analyzer.
  6. Optional. Add any tags that you want to apply to the analyzer.
  7. Choose Create Analyzer.
  
  **From Command Line:**  
  Run the following command:
  
      aws accessanalyzer create-analyzer --analyzer-name --type
  
  **Note:** The IAM Access Analyzer is successfully configured only when the account you use has the necessary permissions.`,
  
  references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html',
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html',
      'https://docs.aws.amazon.com/cli/latest/reference/accessanalyzer/get-analyzer.html',
      'https://docs.aws.amazon.com/cli/latest/reference/accessanalyzer/create-analyzer.html',
  ],
  gql: `{
    queryawsAccount {
      id
      arn
      accountId
      __typename
      regions
      iamAccessAnalyzers {
        region
        status
      }
    }
  }`,
  resource: 'queryawsAccount[*]',
  severity: 'high',
  conditions: {
    and: [
      {
        path: '@.iamAccessAnalyzers',
        isEmpty: false,
      },
      {
        path: '@',
        jq: '[.regions[] as $scanned | { scannedRegion: $scanned, analyzers: [.iamAccessAnalyzers[] | select(.region == $scanned )] }]',
        array_all: {
          path: '[*].analyzers[0].status',
          equal: 'ACTIVE',
        },
      },
    ],
  },
}