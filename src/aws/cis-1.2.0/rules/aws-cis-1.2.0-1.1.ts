export default {
  id: 'aws-cis-1.2.0-1.1',
  title:
    "AWS CIS 1.1 Avoid the use of 'root' account. Show used in last 30 days",
  description: `The "root" account has unrestricted access to all resources in the AWS account. It is highly
    recommended that the use of this account be avoided.`,
  audit: `Implement the *Ensure a log metric filter and alarm exist for usage of "root" account* recommendation in the *Monitoring* section of this benchmark to receive notifications of root account usage. Additionally, executing the following commands will provide ad-hoc means for determining the last time the root account was used:

  <br/>

    aws iam generate-credential-report

  <br/>

    aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,5,11,16 | grep -B1 '<root_account>'

  <br/>

Note: there are a few conditions under which the use of the root account is required, such as requesting a penetration test or creating a CloudFront private key.`,
  rationale: `The "root" account is the most privileged AWS account. Minimizing the use of this account and adopting the principle of least privilege for access management will reduce the risk of accidental changes and unintended disclosure of highly privileged credentials.`,
  remediation: `Follow the remediation instructions of the Ensure IAM policies are attached only to groups or roles recommendation`,
  references: [
    `http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html`,
    `CIS CSC v6.0 #5`,
  ],
  gql: `{
    queryawsIamUser(filter: { name: { eq: "root" } }) {
      id
      arn
      accountId
       __typename
      passwordLastUsed
      passwordEnabled
    }
  }`,
  exclude: { not: { path: '@.name', equal: 'root' } },
  resource: 'queryawsIamUser[*]',
  severity: 'high',
  conditions: {
    not: {
      and: [
        {
          path: '@.passwordEnabled',
          equal: true,
        },
        {
          value: { daysAgo: {}, path: '@.passwordLastUsed' },
          lessThanInclusive: 30,
        },
      ],
    },
  },
}
