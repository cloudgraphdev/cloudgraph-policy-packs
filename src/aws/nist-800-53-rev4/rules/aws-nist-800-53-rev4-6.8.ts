export default {
  id: 'aws-nist-800-53-rev4-6.8',
  title:
    'AWS NIST 6.8 Exactly one CloudTrail trail should monitor global services',

  description:
    'For global services such as AWS Identity and Access Management (IAM), AWS STS, and Amazon CloudFront, events are delivered to any trail that includes global services. If you have multiple single region trails, AWS recommends configuring your trails so that global service events are delivered in only one of the trails.',

  audit: '',

  rationale: '',

  remediation: `**AWS Console**

  If you have multiple single region trails, AWS recommends configuring your trails so that global service events are delivered in only one of the trails.

  Global service events are delivered by default to trails that are created using the CloudTrail console, and cannot be configured using the console. Use the CLI for remediation instead.

  **AWS CLI**

  To disable global service events for a CloudTrail trail, replace MYTRAILNAME with your trail name:

      aws cloudtrail update-trail --name MYTRAILNAME --no-include-global-service-events`,

  references: [
    'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-global-service-events',
    'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail-by-using-the-aws-cli-update-trail.html#cloudtrail-create-and-update-a-trail-by-using-the-aws-cli-examples-gses',
  ],
  gql: `{
    queryawsAccount {
      id
      __typename
      cloudtrail {
        includeGlobalServiceEvents
      }
    }
  }`,
  resource: 'queryawsAccount[*]',
  severity: 'medium',
  check: ({ resource }: any) =>
    resource.cloudtrail?.filter(
      (ct: any) => ct.includeGlobalServiceEvents === 'Yes'
    ).length === 1,
}
