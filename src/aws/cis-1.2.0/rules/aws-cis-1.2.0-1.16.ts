export default {
  id: 'aws-cis-1.2.0-1.16',
  description:
    'AWS CIS 1.16 Ensure IAM policies are attached only to groups or roles (Scored)',
  audit: `Perform the following to determine if policies are attached directly to users:

  1. Run the following to get a list of IAM users:
  
  aws iam list-users --query 'Users[*].UserName' --output text
  
  2. For each user returned, run the following command to determine if any policies are attached to them:
  
  aws iam list-attached-user-policies --user-name <iam_user>
  aws iam list-user-policies --user-name <iam_user>
  
  3. If any policies are returned, the user has a direct policy attachment.`,
  rationale: `Assigning privileges at the group or role level reduces the complexity of access management as the number of users grows. Reducing access management complexity may in turn reduce the opportunity for a principal to inadvertently receive or retain excessive privileges.`,
  remediation: `Perform the following to create an IAM group and assign a policy to it:

  1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
  2. In the navigation pane, click Groups and then click Create New Group.
  3. In the Group Name box, type the name of the group and then click Next Step.
  4. In the list of policies, select the check box for each policy that you want to apply to all members of the group. Then click Next Step.
  5. Click Create Group
  
  Perform the following to add a user to a given group:
  
  1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
  2. In the navigation pane, click Groups
  3. Select the group to add a user to
  4. Click Add Users To Group
  5. Select the users to be added to the group
  6. Click Add Users
  
  Perform the following to remove a direct association between a user and policy:
  
  1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
  2. In the left navigation pane, click on Users
  3. For each user:
      1. Select the user
      2. Click on the Permissions tab
      3. Expand Managed Policies
      4. Click Detach Policy for each policy
      5. Expand Inline Policies
      6. Click Remove Policy for each policy`,
  references: [
    `http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html`,
    `http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html`,
    `CCE- 78912 - 3`,
  ],
  gql: `{
    queryawsIamUser {
      id
      __typename
      iamAttachedPolicies {
        name
      },
      inlinePolicies
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.iamAttachedPolicies',
        isEmpty: true,
      },
      {
        path: '@.inlinePolicies',
        isEmpty: true,
      },
    ],
  },
}
