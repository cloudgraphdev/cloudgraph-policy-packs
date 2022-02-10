/* eslint-disable max-len */
export default {
  id: 'aws-cis-1.2.0-1.20',
  title:
    'AWS CIS 1.20 Ensure a support role has been created to manage incidents with AWS Support',
  description:
    'AWS provides a support center that can be used for incident notification and response, as well as technical support and customer services. Create an IAM Role to allow authorized users to manage incidents with AWS Support.',
  audit: `Using the Amazon unified command line interface:

  - List IAM policies, filter for the 'AWSSupportAccess' managed policy, and note the "Arn" element value:,

          aws iam list-policies --query "Policies[?PolicyName == 'AWSSupportAccess']"

  - Check if the 'AWSSupportAccess' is attached to any IAM user, group or role:

          aws iam list-entities-for-policy --policy-arn <iam_policy_arn>`,

  rationale:
    'By implementing least privilege for access control, an IAM Role will require an appropriate IAM Policy to allow Support Center Access in order to manage Incidents with AWS Support.',

  remediation: `Using the Amazon unified command line interface:

  - Create an IAM role for managing incidents with AWS:
    - Create a trust relationship policy document that allows <iam_user> to manage AWS incidents, and save it locally as /tmp/TrustPolicy.json:

              {
                  "Version": "2012- 10 - 17",
                  "Statement": [
                      {
                          "Effect": "Allow",
                          "Principal": {
                              "AWS": "<iam_user>"
                          },
                          "Action": "sts:AssumeRole"
                      }
                  ]
              }

    - Create the IAM role using the above trust policy:

              aws iam create-role --role-name <aws_support_iam_role> --assume-role-policy-document file:///tmp/TrustPolicy.json

    - Attach 'AWSSupportAccess' managed policy to the created IAM role:

              aws iam attach-role-policy --policy-arn <iam_policy_arn> --role-name <aws_support_iam_role>`,

  references: [
    'http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html',
    'https://aws.amazon.com/premiumsupport/pricing/',
    'http://docs.aws.amazon.com/cli/latest/reference/iam/list-policies.html',
    'http://docs.aws.amazon.com/cli/latest/reference/iam/attach-role-policy.html',
    'http://docs.aws.amazon.com/cli/latest/reference/iam/list-entities-for-policy.html',
  ],
  gql: `{
    queryawsIamPolicy(filter: { name: { eq: "AWSSupportAccess" } }) {
      id
      arn
      accountId
       __typename
      name
      iamUsers {
        arn
      }
      iamGroups {
        arn
      }
      iamRoles {
        arn
      }
    }
  }`,
  resource: 'queryawsIamPolicy[*]',
  severity: 'medium',
  conditions: {
    or: [
      {
        path: '@.iamUsers',
        isEmpty: false,
      },
      {
        path: '@.iamGroups',
        isEmpty: false,
      },
      {
        path: '@.iamRoles',
        isEmpty: false,
      },
    ],
  },
}
