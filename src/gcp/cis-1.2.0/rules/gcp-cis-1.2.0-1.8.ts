export default {
  id: 'gcp-cis-1.2.0-1.8',
  title:
    'GCP CIS 1.8 Ensure that Separation of duties is enforced while assigning service account related roles to users',
  description: `It is recommended that the principle of 'Separation of Duties' is enforced while assigning
  service-account related roles to users.`,
  audit: `**From Console:**

  1. Go to *IAM & Admin/IAM* using https://console.cloud.google.com/iam-admin/iam.
  2. Ensure no member has the roles *Service Account Admin and Service account User* assigned together.


  **From Command Line:**

  1. List all users and role assignments:

          gcloud projects get-iam-policy [Project_ID]

  2. Ensure that there are no common users found in the member section for roles *roles/iam.serviceAccountAdmin and roles/iam.serviceAccountUser*`,
  rationale: `The built-in/predefined IAM role *Service Account admin* allows the user/identity to create, delete, and manage service account(s). The built-in/predefined IAM role *Service Account User* allows the user/identity (with adequate privileges on Compute and App Engine) to assign service account(s) to Apps/Compute Instances.

  Separation of duties is the concept of ensuring that one individual does not have all necessary permissions to be able to complete a malicious action. In Cloud IAM - service accounts, this could be an action such as using a service account to access resources that user should not normally have access to.

  Separation of duties is a business control typically used in larger organizations, meant to help avoid security or privacy incidents and errors. It is considered best practice.

  No user should have *Service Account Admin* and *Service Account User* roles assigned at the same time.`,
  remediation: `**From Console:**

  1. Go to *IAM & Admin/IAM* using https://console.cloud.google.com/iam-admin/iam.
  2. For any member having both *Service Account Admin* and *Service account User* roles granted/assigned, click the *Delete Bin* icon to remove either role from the member. Removal of a role should be done based on the business requirements.`,
  references: [
    `https://cloud.google.com/iam/docs/service-accounts`,
    `https://cloud.google.com/iam/docs/understanding-roles`,
    `https://cloud.google.com/iam/docs/granting-roles-to-service-accounts`,
  ],
  gql: `{
    querygcpProject {
      id
      __typename
      iamPolicies {
        bindings {
          role
          members
       }
      }
    }
  }`,
  resource: 'querygcpProject[*]',
  severity: 'unknown',
  conditions: {
    not: {
      path: '@.iamPolicies',
      array_any: {
        path: '[*].bindings',
        array_any: {
          and: [
            {
              path: '[*].members',
              match: /user.*$/,
            },
            {
              path: '[*].role',
              in: [
                'roles/iam.serviceAccountAdmin',
                'roles/iam.serviceAccountUser',
              ],
            },
          ],
        },
      },
    },
  },
}
