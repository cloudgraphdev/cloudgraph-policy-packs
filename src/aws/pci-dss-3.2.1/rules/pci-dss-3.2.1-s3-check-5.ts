export default {
  id: 'aws-pci-dss-3.2.1-s3-check-5',
  title:
    'S3 Check 5: S3 buckets should require requests to use Secure Socket Layer',
  description: `This control checks whether Amazon S3 buckets have policies that require requests to use Secure Socket Layer (SSL).

  S3 buckets should have policies that require all requests (Action: S3:*) to only accept transmission of data over HTTPS in the S3 resource policy, indicated by the condition key aws:SecureTransport.

  This does not check the SSL or TLS version. You should not allow early versions of SSL or TLS (SSLv3, TLS1.0) per PCI DSS requirements.`,
  rationale: `
  This control is related to the following PCI DSS requirements.

  **PCI DSS 4.1 Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission over open, public networks.**

  If you use S3 buckets to store cardholder data, ensure that bucket policies require that requests to the bucket only accept transmission of data over HTTPS. For example, you could use the policy statement "aws:SecureTransport": "false" to deny any requests not accessed through HTTPS. Allowing unencrypted transmissions of cardholder data might violate the requirement to use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission over open, public networks.`,
  remediation: `To remediate this issue, update the permissions policy of the S3 bucket.

  **To configure an S3 bucket to deny nonsecure transport**

  1. Open the Amazon S3 console at https://console.aws.amazon.com/s3/.
  2. Navigate to the noncompliant bucket, and then choose the bucket name.
  3. Choose **Permissions**, then choose **Bucket Policy**.
  4. Add a similar policy statement to that in the policy below. Replace awsexamplebucket with the name of the bucket you are modifying.

      {
          "Id": "ExamplePolicy",
          "Version": "2012-10-17",
          "Statement": [
              {
                  "Sid": "AllowSSLRequestsOnly",
                  "Action": "s3:*",
                  "Effect": "Deny",
                  "Resource": [
                      "arn:aws:s3:::awsexamplebucket",
                      "arn:aws:s3:::awsexamplebucket/*"
                  ],
                  "Condition": {
                      "Bool": {
                          "aws:SecureTransport": "false"
                      }
                  },
                "Principal": "*"
              }
          ]
      }

  5. Choose **Save**.

  For more information, see the knowledge center article [What S3 bucket policy should I use to comply with the AWS Config rule s3-bucket-ssl-requests-only?](http://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/).`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-s3-5',
    'http://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/',
  ],
  gql: `{
    queryawsS3 {
      id
      arn
      accountId
      __typename
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
            value
          }
        }
      }
    }
  }`,
  resource: 'queryawsS3[*]',
  severity: 'medium',
  conditions: {
    path: '@.policy.statement',
    array_any: {
      or: [
        {
          path: '[*].effect',
          equal: 'Deny',
        },
        {
          and: [
            {
              path: '@.[*].condition',
              isEmpty: false,
            },
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
                },
              },
            },
          ],
        },
      ],
    },
  },
}
