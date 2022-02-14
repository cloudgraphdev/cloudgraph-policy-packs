export default {
  id: 'aws-pci-dss-3.2.1-iam-check-3',
  title:
    'IAM Check 3: IAM policies should not allow full "*" administrative privileges',
  description: `This control checks whether the default version of AWS Identity and Access Management policies (also known as customer managed policies) do not have administrator access with a statement that has "Effect": "Allow" with "Action": "_" over "Resource": "_".

  It only checks for the [customer managed policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#customer-managed-policies) that you created, but does not check for full access to individual services, such as "S3:\*".

  It does not check for [inline and AWS managed policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#aws-managed-policies).`,
  rationale: `**PCI DSS 7.2.1: Establish an access control system(s) for systems components that restrict access based on a user’s need to know, and is set to "deny all" unless specifically allowed. This access control system(s) must include the following: Coverage of all system components.**
  Providing full administrative privileges instead of restricting to the minimum required may violate the requirement to ensure access to systems components is restricted to the least privilege necessary, or a user’s need to know.`,
  remediaton: `**To modify an IAM policy**

  1. Open the IAM console at https://console.aws.amazon.com/iam/.

  2. Choose **Policies**.

  3. Choose the radio button next to the policy to remove.

  4. From **Policy actions**, choose **Detach**.

  5. On the **Detach policy** page, choose the radio button next to each user to detach the policy from and then choose **Detach policy**.

  6. Confirm that the user that you detached the policy from can still access AWS services and resources as expected.`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#customer-managed-policies',
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#aws-managed-policies',
  ],
  gql: `{
    queryawsIamPolicy {
      id
      arn
      accountId
       __typename
      policyContent {
        statement {
          effect
          action
          resource
        }
      }
    }
  }`,
  resource: 'queryawsIamPolicy[*]',
  severity: 'high',
  conditions: {
    not: {
      path: '@.policyContent.statement',
      array_any: {
        and: [
          {
            path: '[*].effect',
            equal: 'Allow',
          },
          {
            path: '[*].action',
            contains: '*',
          },
          {
            path: '[*].resource',
            contains: '*',
          },
        ],
      },
    },
  },
}
