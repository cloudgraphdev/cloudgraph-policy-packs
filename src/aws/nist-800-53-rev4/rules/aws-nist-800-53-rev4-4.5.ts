export default {
  id: 'aws-nist-800-53-rev4-4.5',  
  title: 'AWS NIST 4.5 S3 bucket policies should only allow requests that use HTTPS',
  
  description: 'To protect data in transit, an S3 bucket policy should deny all HTTP requests to its objects and allow only HTTPS requests. HTTPS uses Transport Layer Security (TLS) to encrypt data, which preserves integrity and prevents tampering.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [S3](https://console.aws.amazon.com/s3/).
  - Select the S3 bucket.
  - Click the Permissions tab.
  - Select Bucket Policy.
  - In the bucket policy editor, enter the bucket policy that is compliant with the SSL AWS Config rule as documented [here](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-ssl-requests-only.html).
  
  **AWS CLI**
  
  Set bucket policy to only allow HTTPS requests on an S3 Bucket:
  
      aws s3api put-bucket-policy --bucket <bucket value> --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["<account id>"]},"Action":"s3:Get*","Resource":"<bucket arn>/*"},{"Effect":"Deny","Principal":"*","Action":"*","Resource":"<bucket arn>/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'`,
  
  references: [
      'https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-ssl-requests-only.html',
      'https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-policy.html',
  ],  
  gql: `{
    queryawsS3 {
      id
      arn
      accountId
      __typename
      bucketPolicies {
        policy {
          statement {
            effect
            action
            principal {
              key
              value
            }
            condition {
              key
              operator
              value
            }
          }
        }
      }
    }
  }`,
  resource: 'queryawsS3[*]',
  severity: 'medium',
  conditions: { 
    path: '@.bucketPolicies',
    array_all: {
      path: '[*].policy.statement',
      array_any: {
        or: [
          {
            path: '[*].effect',
            equal: 'Deny',
          },
          {
            and: [
              {
                path: '[*].condition',
                array_any: {
                  and: [
                    {
                      path: '[*].key',
                      equal: 'aws:SecureTransport',
                    },
                    {
                      path: '[*].value',
                      contains: 'true',
                    },
                  ],
                },
              },
              {
                path: '[*].principal',
                array_any: {
                  not: {
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
                  }
                },
              },
            ],
          },
        ],
      },
    },
  },
}
