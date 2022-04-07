export default {
  id: 'aws-nist-800-53-rev4-1.1',  
  title: 'AWS NIST 1.1 IAM role trust policies should not allow all principals to assume the role',
  
  description: 'Using a wildcard in the Principal attribute in a role’s trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used by anyone to gain access to an account with potentially sensitive data.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to IAM.
  - Select the role that includes the trust policy.
  - Navigate to the Trust Relationships tab, and select Edit trust relationship.
  - Ensure that the Principal attribute does not include any wildcards (*).
  
  **AWS CLI**
  
  Ensure that IAM trust policies created via CLI do not use wildcards in the Principal attribute:
  
      aws iam update-assume-role-policy --role-name Test-Role --policy-document file://policy.json
  
  policy.json:
  
      {
          "Version": "2012-10-17",
          "Statement": [
              {
                  "Effect": "Allow",
                  "Principal": {
                      "Service": "ec2.amazonaws.com"
                  },
                  "Action": "sts:AssumeRole",
                  "Condition": {}
              }
          ]
      }`,
  
  references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_resource-based',
      'https://docs.aws.amazon.com/cli/latest/reference/iam/update-assume-role-policy.html',
  ],
  gql: `{
    queryawsIamRole {
      id
      arn
      accountId
      __typename
      assumeRolePolicy {
        statement {
          principal {
            key
            value
          }
        }
      }
    }
  }`,
  resource: 'queryawsIamRole[*]',
  severity: 'medium',
  conditions: {
    not: {
      path: '@.assumeRolePolicy.statement',
      array_any: {
        path: '[*].principal',
        array_any: {
          path: '[*].value',
          contains: '*',
        },
      },
    },
  },
}