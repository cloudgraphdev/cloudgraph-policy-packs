// AWS CIS 1.2.0 Rule equivalent 1.22
export default {
  id: 'aws-cis-1.5.0-1.16',  
  title: 'AWS CIS 1.16 Ensure IAM policies that allow full "*:*" administrative privileges are not attached',
  
  description: 'IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege -that is, granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges.',
  
  audit: `Perform the following to determine what policies are created:
  
  **From Command Line:**
  
  1. Run the following to get a list of IAM policies:
  
          aws iam list-policies --only-attached --output text
  
  2. For each policy returned, run the following command to determine if any policies is allowing full administrative privileges on the account:
  
          aws iam get-policy-version --policy-arn <policy_arn> --version-id <version>
  
  3. In output ensure policy should not have any Statement block with "Effect": "Allow" and Action set to "*" and Resource set to "*"`,
  
  rationale: `It's more secure to start with a minimum set of permissions and grant additional permissions as necessary, rather than starting with permissions that are too lenient and then trying to tighten them later.
  
  Providing full administrative privileges instead of restricting to the minimum set of permissions that the user is required to do exposes the resources to potentially unwanted actions.
  
  IAM policies that have a statement with "Effect": "Allow" with "Action": "*" over "Resource": "*" should be removed.`,
  
  remediation: `**From Console:**
  Perform the following to detach the policy that has full administrative privileges:
  
  1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
  2. In the navigation pane, click Policies and then search for the policy name found in the audit step.
  3. Select the policy that needs to be deleted.
  4. In the policy action menu, select first Detach
  5. Select all Users, Groups, Roles that have this policy attached
  6. Click Detach Policy
  7. In the policy action menu, select Detach
  
  **From Command Line:**
  Perform the following to detach the policy that has full administrative privileges as found in the audit step:
  
  1. Lists all IAM users, groups, and roles that the specified managed policy is attached to.
  
          aws iam list-entities-for-policy --policy-arn <policy_arn>
  
  2. Detach the policy from all IAM Users:
  
          aws iam detach-user-policy --user-name <iam_user> --policy-arn <policy_arn>
  
  3. Detach the policy from all IAM Groups:
  
          aws iam detach-group-policy --group-name <iam_group> --policy-arn <policy_arn>
  
  4. Detach the policy from all IAM Roles:
  
          aws iam detach-role-policy --role-name <iam_role> --policy-arn <policy_arn>`,
  
  references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html',
      'CCE-78912-3',
      'https://docs.aws.amazon.com/cli/latest/reference/iam/index.html#cli-aws-iam',
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
