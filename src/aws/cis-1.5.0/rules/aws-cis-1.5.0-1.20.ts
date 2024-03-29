export default {
  id: 'aws-cis-1.5.0-1.20',
  title:
    'AWS CIS 1.20 Ensure that IAM Access analyzer is enabled for all regions',

  description: `Enable IAM Access analyzer for IAM policies about all resources in each region.

  IAM Access Analyzer is a technology introduced at AWS reinvent 2019. After the Analyzer is enabled in IAM, scan results are displayed on the console showing the accessible resources. Scans show resources that other accounts and federated users can access, such as KMS keys and IAM roles. So the results allow you to determine if an unintended user is allowed, making it easier for administrators to monitor least privileges access. Access Analyzer analyzes only policies that are applied to resources in the same AWS Region.`,

  audit: `**From Console:**

  1. Open the IAM console at https://console.aws.amazon.com/iam/
  2. Choose *Access analyzer*
  3. Click *Analyzers*
  4. Ensure that at least one analyzer is present
  5. Ensure that the *STATUS* is set to *Active*
  6. Repeat these step for each active region

  **From Command Line:**

  1. Run the following command:

          aws accessanalyzer list-analyzers | grep status

  2. Ensure that at least one Analyzer the status is set to ACTIVE
  3. Repeat the steps above for each active region.

  If an Access analyzer is not listed for each region or the status is not set to active refer to the remediation procedure below.',

  rationale: 'AWS IAM Access Analyzer helps you identify the resources in your organization and accounts, such as Amazon S3 buckets or IAM roles, that are shared with an external entity. This lets you identify unintended access to your resources and data. Access Analyzer identifies resources that are shared with external principals by using logic-based reasoning to analyze the resource-based policies in your AWS environment. IAM Access Analyzer continuously monitors all policies for S3 bucket, IAM roles, KMS(Key Management Service) keys, AWS Lambda functions, and Amazon SQS(Simple Queue Service) queues.`,

  remediation: `**From Console:**
  Perform the following to enable IAM Access analyzer for IAM policies:

  1. Open the IAM console at https://console.aws.amazon.com/iam/.
  2. Choose *Access analyzer*.
  3. Choose *Create analyzer*.
  4. On the *Create analyzer* page, confirm that the Region displayed is the *Region* where you want to enable Access Analyzer.
  5. Enter a name for the analyzer. *Optional as it will generate a name for you automatically*.
  6. Add any tags that you want to apply to the analyzer. *Optional*.
  7. Choose *Create Analyzer*.
  8. Repeat these step for each active region

  **From Command Line:**
  Run the following command:

      aws accessanalyzer create-analyzer --analyzer-name <NAME> --type <ACCOUNT|ORGANIZATION>

  Repeat this command above for each active region.
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
  check: ({ resource }: any) => {
    const regionsWithAnalyzer: { [region: string]: boolean } = {}
    resource.iamAccessAnalyzers?.forEach((a: any) => {
      if (a.status === 'ACTIVE') {
        regionsWithAnalyzer[a.region] = true
      }
    })
    return resource.regions?.every(
      (region: string) => regionsWithAnalyzer[region]
    )
  },
}
