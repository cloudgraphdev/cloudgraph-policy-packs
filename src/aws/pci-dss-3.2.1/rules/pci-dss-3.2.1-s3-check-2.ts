export default {
  id: 'aws-pci-dss-3.2.1-s3-check-2',
  title: 'S3 Check 2: S3 buckets should prohibit public read access',
  description: `This control checks whether your S3 buckets allow public read access by evaluating the Block Public Access settings, the bucket policy, and the bucket access control list (ACL).

  Unless you explicitly require everyone on the internet to be able to write to your S3 bucket, you should ensure that your S3 bucket is not publicly writable.

  It does not check for read access to the bucket by internal principals, such as IAM roles. You should ensure that access to the bucket is restricted to authorized principals only.`,
  rationale: `This control is related to the following PCI DSS requirements:

  **PCI DSS 1.2.1: Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment (CDE), and specifically deny all other traffic.**

  If you use an S3 bucket to store cardholder data, the bucket should prohibit public read access. Public read access might violate the requirement to allow only necessary traffic to and from the CDE.

  **PCI DSS 1.3.1: Implement a DMZ to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports.**

  If you use an S3 bucket to store cardholder data, the bucket should prohibit public read access. Public read access might violate the requirement to limit inbound traffic to only system components that provide authorized publicly accessible services, protocols, and ports.

  **PCI DSS 1.3.2: Limit inbound internet traffic to IP addresses within the DMZ.**

  If you use an S3 bucket to store cardholder data, the bucket should prohibit public read access. Public read access might violate the requirement to limit inbound internet traffic to IP addresses within the DMZ.

  **PCI DSS 1.3.6: Place system components that store cardholder data (such as a database) in an internal network zone, segregated from the DMZ and other untrusted networks.**

  If you use an S3 bucket to store cardholder data, the bucket should prohibit public read access. Public read access might violate the requirement to place system components that store cardholder data in an internal network zone, segregated from the DMZ and other untrusted networks.

  **PCI DSS 7.2.1: Establish an access control system(s) for systems components that restricts access based on a user’s need to know, and is set to "deny all" unless specifically allowed. This access control system(s) must include the following: Coverage of all system components.**

  If you use an S3 bucket to store cardholder data, the bucket should prohibit public read access. Public read access might violate the requirement to ensure access to systems components is restricted to least privilege necessary, or a user’s need to know.
  `,
  remediation: `**To remove public access for an S3 bucket**

  1. Open the Amazon S3 console at https://console.aws.amazon.com/s3/.
  2. Choose the name of the bucket identified in the finding.
  3. Choose **Permissions** and then choose Public access settings.
  4. Choose **Edit**, select all four options, and then choose **Save**.
  5. If prompted, enter **confirm** and then choose **Confirm**.`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-s3-2',
  ],
  gql: `{
    queryawsS3 {
      id
      arn
      accountId
      __typename
      blockPublicPolicy
      blockPublicAcls
      policy {
        statement {
          action
          effect
          principal {
            key
            value
          }
        }
      }
    }
  }`,
  resource: 'queryawsS3[*]',
  severity: 'high',
  conditions: {
    and: [
      {
        path: '@.blockPublicPolicy',
        equal: 'Yes',
      },
      {
        path: '@.blockPublicAcls',
        equal: 'Yes',
      },
      {
        path: '@.policy.statement',
        array_all: {
          not: {
            and: [
              {
                path: '[*].effect',
                equal: 'Allow',
              },
              {
                or: [
                  {
                    path: '[*].action',
                    contains: '*',
                  },
                  {
                    path: '[*].action',
                    contains: 's3:GetObject',
                  },
                  {
                    path: '[*].action',
                    contains: 's3:GetObjectVersion',
                  },
                  {
                    path: '[*].action',
                    contains: 's3:ListBucket',
                  },
                  {
                    path: '[*].action',
                    contains: 's3:ListBucketVersions',
                  },
                ],
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
                      or: [
                        {
                          path: '[*].value',
                          contains: '*',
                        },
                        {
                          path: '[*].value',
                          matchAny: /\s*:root\s*/,
                        },
                      ],
                    },
                  ],
                },
              },
            ],
          },
        },
      },
    ],
  },
}
