// AWS CIS 1.2.0 Rule equivalent 2.3
export default {
  id: 'aws-cis-1.3.0-3.3',
  title:
    'AWS CIS 3.3 Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible',
  description:
    'CloudTrail logs a record of every API call made in your AWS account. These logs file are stored in an S3 bucket. It is recommended that the bucket policy, or access control list (ACL), applied to the S3 bucket that CloudTrail logs to prevents public access to the CloudTrail logs.',
  audit: `Perform the following to determine if any public access is granted to an S3 bucket via an ACL or S3 bucket policy: Via the Management Console

  1. Go to the Amazon CloudTrail console at https://console.aws.amazon.com/cloudtrail/home
  2. In the API activity history pane on the left, click Trails
  3. In the Trails pane, note the bucket names in the S3 bucket column
  4. Go to Amazon S3 console at https://console.aws.amazon.com/s3/home
  5. For each bucket noted in step 3, right-click on the bucket and click Properties
  6. In the Properties pane, click the Permissions tab.
  7. The tab shows a list of grants, one row per grant, in the bucket ACL. Each row identifies the grantee and the permissions granted.
  8. Ensure no rows exists that have the Grantee set to Everyone or the Grantee set to Any Authenticated User.
  9. If the Edit bucket policy button is present, click it to review the bucket policy.
  10. Ensure the policy does not contain a Statement having an Effect set to Allow and a Principal set to "*" or {"AWS" : "*"}

  Via CLI:

  1. Get the name of the S3 bucket that CloudTrail is logging to:

          aws cloudtrail describe-trails --query 'trailList[*].S3BucketName'

  2. Ensure the AllUsers principal is not granted privileges to that <bucket> :

          aws s3api get-bucket-acl --bucket <s3_bucket_for_cloudtrail> --query 'Grants[?Grantee.URI== http://acs.amazonaws.com/groups/global/AllUsers ]'

  3. Ensure the AuthenticatedUsers principal is not granted privileges to that <bucket> :

          aws s3api get-bucket-acl --bucket <s3_bucket_for_cloudtrail> --query 'Grants[?Grantee.URI== http://acs.amazonaws.com/groups/global/Authenticated Users ]'

  4. Get the S3 Bucket Policy

          aws s3api get-bucket-policy --bucket <s3_bucket_for_cloudtrail>

  5. Ensure the policy does not contain a Statement having an Effect set to Allow and a Principal set to "*" or {"AWS" : "*"}

  Note: Principal set to "*" or {"AWS" : "*"} allows anonymous access.`,
  rationale:
    'Allowing public access to CloudTrail log content may aid an adversary in identifying weaknesses in the affected account`s use or configuration.',
  remediation: `Perform the following to remove any public access that has been granted to the bucket via an ACL or S3 bucket policy:

  1. Go to Amazon S3 console at https://console.aws.amazon.com/s3/home
  2. Right-click on the bucket and click Properties
  3. In the Properties pane, click the Permissions tab.
  4. The tab shows a list of grants, one row per grant, in the bucket ACL. Each row identifies the grantee and the permissions granted.
  5. Select the row that grants permission to Everyone or Any Authenticated User
  6. Uncheck all the permissions granted to Everyone or Any Authenticated User (click x to delete the row).
  7. Click Save to save the ACL.
  8. If the Edit bucket policy button is present, click it.
  9. Remove any Statement having an Effect set to Allow and a Principal set to "*" or {"AWS" : "*"}.`,
  references: [
    'CCE-78915-6',
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html',
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
  severity: 'medium',
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
