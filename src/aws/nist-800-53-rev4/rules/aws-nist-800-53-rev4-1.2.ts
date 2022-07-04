export default {
  id: 'aws-nist-800-53-rev4-1.2',
  title:
    'AWS NIST 1.2 IAM roles attached to instance profiles should not allow broad list actions on S3 buckets',

  description:
    'Instance profiles contain trust policies that enable EC2 instances to assume IAM roles. To prevent compromised EC2 instances from being able to effectively survey all S3 buckets and potentially access sensitive data, trust policies attached to instance profiles should not allow broad list actions on S3 buckets, such as ListAllBuckets',

  audit: '',

  rationale: '',

  remediation: `**AWS Console**

  - Navigate to [IAM](https://console.aws.amazon.com/iam/).
  - Select the [role](https://console.aws.amazon.com/iam/home#/roles) that is associated with an instance profile. You should see an Instance Profile ARN within the role summary.
  - Select the attached policy that includes S3 list actions, and ensure that broad list actions (ListBuckets, S3:List*, S3:*) are not included.

  **AWS CLI**

  Ensure that IAM policies attached to IAM roles associated with instance profiles do not include broad S3 list actions:

      aws iam update-policy --policy-id PolicyID --policy-document file://policy.json

  policy.json:

      {
          "Version": "2012-10-17",
          "Statement": [
              {
                  "Action": "s3:Get*",
                  "Effect": "Allow",
                  "Resource": "*"
              }
          ]
      }`,

  references: [
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html',
    'https://docs.aws.amazon.com/cli/latest/reference/iam/update-assume-role-policy.html',
  ],
  gql: `{
    queryawsIamRole(filter: { has : iamInstanceProfiles }) {
      id
      arn
      accountId
      __typename
      iamInstanceProfiles {
        arn
      }
      iamAttachedPolicies {
        policyContent {
          statement {
            effect
            action
          }
        }
      }
    }
  }`,
  exclude: { path: '@.iamInstanceProfiles', isEmpty: true },
  resource: 'queryawsIamRole[*]',
  severity: 'medium',
  conditions: {
    not: {
      path: '@.iamAttachedPolicies',
      array_any: {
        path: '[*].policyContent.statement',
        array_any: {
          and: [
            {
              path: '[*].effect',
              equal: 'Allow',
            },
            {
              or: [
                {
                  path: '[*].action',
                  contains: 'ListBuckets',
                },
                {
                  path: '[*].action',
                  contains: 'S3:List*',
                },
                {
                  path: '[*].action',
                  contains: 'S3:*',
                },
              ],
            },
          ],
        },
      },
    },
  },
}
