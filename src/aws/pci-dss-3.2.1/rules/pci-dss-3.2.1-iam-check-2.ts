export default {
  id: 'aws-pci-dss-3.2.1-iam-check-2',
  title: 'IAM Check 2: IAM users should not have IAM policies attached',
  description: `This control checks that none of your IAM users have policies attached. IAM users must inherit permissions from IAM groups or roles.

  It does not check whether least privileged policies are applied to IAM roles and groups.`,
  rationale: `**PCI DSS 7.2.1: Establish an access control system(s) for systems components that restricts access based on a user’s need to know, and is set to "deny all" unless specifically allowed. This access control system(s) must include the following: Coverage of all system components.**
  IAM policies are how privileges are granted to users, groups, or roles in AWS.

  By default, IAM users, groups, and roles have no access to AWS resources until IAM policies are attached to them.

  To manage least privileged access and reduce the complexity of access management for PCI DSS in-scope resources, you should assign IAM polices at the group or role level and not at the user level.

  Reducing access management complexity reduces opportunity for a principal to inadvertently receive or retain excessive privileges.

  This is a method used to ensure access to systems components that contain cardholder data is restricted to least privilege necessary, or a user’s need to know.`,
  remediaton: `To resolve this issue, do the following:

  1. Create an IAM group

  2. Assign the policy to the group

  3. Add the users to the group

  The policy is applied to each user in the group.

  **To create an IAM group**

  1. Open the IAM console at https://console.aws.amazon.com/iam/.

  2. Choose **Groups** and then choose **Create New Group**.

  3. Enter a name for the group to create and then choose **Next Step**.

  4. Select each policy to assign to the group and then choose **Next Step**.

  The policies that you choose should include any policies currently attached directly to a user account. The next step to resolve a failed check is to add users to a group and then assign the policies to that group.

  Each user in the group gets assigned the policies assigned to the group.

  5. Confirm the details on the **Review** page and then choose **Create Group**.

  For more information about creating IAM groups, see the [IAM User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups_create.html).

  **To add users to an IAM group**

  1. Open the IAM console at https://console.aws.amazon.com/iam/.

  2. Choose **Groups**.

  3. Choose **Group Actions** and then choose **Add Users to Group**.

  4. Choose the users to add to the group and then choose **Add Users**.

  For more information about adding users to groups, see the [IAM User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups_manage_add-remove-users.html).

  **To remove a policy attached directly to a user**

  1. Open the IAM console at https://console.aws.amazon.com/iam/.

  2. Choose **Users**.

  3. For the user to detach a policy from, in the **User name** column, choose the name.

  4. For each policy listed under **Attached directly**, to remove the policy from the user, choose the **X** on the right side of the page and then choose **Remove**.

  5. Confirm that the user can still use AWS services as expected.`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups_create.html',
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups_manage_add-remove-users.html',
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups_manage_add-remove-users.html',
  ],
  gql: `{
    queryawsIamUser {
      id
      arn
      accountId
      __typename
      inlinePolicies
      iamAttachedPolicies {
        id
      }
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'low',
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
