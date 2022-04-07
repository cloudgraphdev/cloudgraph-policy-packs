export default {
  id: 'aws-cis-1.2.0-1.4',
  title: 'AWS CIS 1.4 Ensure access keys are rotated every 90 days or less',
  description: `Access keys consist of an access key ID and secret access key, which are used to sign
  programmatic requests that you make to AWS. AWS users need their own access keys to
  make programmatic calls to AWS from the AWS Command Line Interface (AWS CLI), Tools
  for Windows PowerShell, the AWS SDKs, or direct HTTP calls using the APIs for individual
  AWS services. It is recommended that all access keys be regularly rotated.`,
  audit: `Perform the following to determine if access keys are rotated as prescribed:

  1. Login to the AWS Management Console
  2. Click Services
  3. Click IAM
  4. Click on Credential Report
  5. This will download an .xls file which contains Access Key usage for all IAM users within an AWS Account - open this file
  6. Focus on the following columns (where x = 1 or 2)
 - *access_key_X_active*
 - *access_key_X_last_rotated*

  7. Ensure all active keys have been rotated within 90 days

Via CLI

    aws iam generate-credential-report
    aws iam get-credential-report --query 'Content' --output text | base64 -d
`,
  rationale: `Rotating access keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used. Access keys should be rotated to ensure that data cannot be accessed with an old key which might have been lost, cracked, or stolen.`,
  remediation: `Perform the following to rotate access keys:

  1. Login to the AWS Management Console:
  2. Click *Services*
  3. Click *IAM*
  4. Click on *Users*
  5. Click on *Security Credentials*
  6. As an Administrator
  - Click on *Make Inactive* for keys that have not been rotated in 90 Days
  7. As an IAM User
  - Click on *Make Inactive* or *Delete* for keys which have not been rotated or used in 90 Days
  8. Click on *Create Access Key*
  9. Update programmatic call with new *Access Key* credentials

    Via CLI

      aws iam update-access-key
      aws iam create-access-key
      aws iam delete-access-key
  `,
  references: [`CCE- 78902 - 4`],
  gql: `{
    queryawsIamUser {
      id
       arn
      accountId
       __typename
      accessKeyData {
        status
        lastRotated
      }
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'medium',
  conditions: {
    or: [
      {
        path: '@.accessKeyData',
        isEmpty: true
      },
      {
        path: '@.accessKeyData',
        array_any: {
          and: [
            {
              value: { daysAgo: {}, path: '[*].lastRotated' },
              lessThanInclusive: 90,
            },

            { path: '[*].status', equal: 'Active' },
          ],
        },
      }
    ]
  },
}
