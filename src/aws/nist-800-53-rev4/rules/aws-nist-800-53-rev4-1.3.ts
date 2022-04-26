export default {
  id: 'aws-nist-800-53-rev4-1.3',
  title: 'AWS NIST 1.3 S3 bucket ACLs should not have public access on S3 buckets that store CloudTrail log files',

  description: 'CloudTrail logs a record of every API call made in your AWS account to S3 buckets. It is recommended that the bucket policy, or access control list (ACL), applied to these S3 buckets should prevent public access. Allowing public access to CloudTrail log data may aid an adversary in identifying weaknesses in the affected account’s use or configuration.',

  audit: '',

  rationale: '',

  remediation: `**AWS Console**

  - Navigate to [S3](https://console.aws.amazon.com/s3/home).
  - Click the target S3 bucket.
  - Select the Permissions tab.
  - Click Access Control List.
  - In Public access, ensure no rows exist that have the Grantee set to Everyone or the Grantee set to Any Authenticated User.
  - Click Save.
  - Select the Bucket Policy tab.
  - Ensure the policy does not contain a Statement having an Effect set to Allow and a Principal set to "*" or {"AWS" : "*"}
    - Note: Principal set to "*" or {"AWS" : "*"} allows anonymous access.

  **AWS CLI**

  Get the name of the S3 bucket that CloudTrail is logging to:

      aws cloudtrail describe-trails --query 'trailList[*].S3BucketName'

  Ensure the AllUsers principal is not granted privileges to that <bucket> :

      aws s3api get-bucket-acl --bucket <s3_bucket_for_cloudtrail> --query 'Grants[?Grantee.URI== http://acs.amazonaws.com/groups/global/AllUsers]'

  Ensure the AuthenticatedUsers principal is not granted privileges to that <bucket>:

      aws s3api get-bucket-acl --bucket <s3_bucket_for_cloudtrail> --query 'Grants[?Grantee.URI== http://acs.amazonaws.com/groups/global/Authenticated Users]'

  Get the S3 Bucket Policy:

      aws s3api get-bucket-policy --bucket <s3_bucket_for_cloudtrail>

  Ensure the policy does not contain a Statement having an Effect set to Allow and a Principal set to "*" or {"AWS" : "*"}

  Note: Principal set to "*" or {"AWS" : "*"} allows anonymous access`,

  references: [
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html',
      'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/set-bucket-permissions.html',
      'https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/index.html#cli-aws-cloudtrail',
      'https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-acl.html#description',
  ],
  gql: `{
    queryawsCloudtrail {
      id
      arn
      accountId
      __typename
      s3 {
        policy {
          statement {
            effect
            principal {
              key
              value
            }
          }
        }
      }
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'high',
  conditions: {
    not: {
      path: '@.s3',
      array_any: {
        path: '[*].policy.statement',
        array_any: {
          and: [
            {
              path: '[*].effect',
              equal: 'Allow',
            },
            {
              path: '[*].principal',
              array_any: {
                and: [
                  {
                    path: '[*].key',
                    in: ['', 'AWS'],
                  },
                  {
                    path: '[*].value',
                    contains: '*',
                  },
                ],
              },
            },
          ],
        },
      },
    },
  },
}