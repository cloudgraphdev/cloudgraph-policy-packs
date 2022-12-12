export default {
  id: 'gcp-cis-1.3.0-1.6',
  title:
    'GCP CIS 1.6 Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level',
  description: `It is recommended to assign the Service Account User (iam.serviceAccountUser) and
  Service Account Token Creator (iam.serviceAccountTokenCreator) roles to a user for
  a specific service account rather than assigning the role to a user at project level.`,
  audit: `**From Console:**

  1. Go to the IAM page in the GCP Console by visiting https://console.cloud.google.com/iam-admin/iam
  2. Click on the filter table text bar, Type *Role: Service Account User*.
  3. Ensure no user is listed as a result of the filter.
  4. Click on the filter table text bar, Type *Role: Service Account Token Creator*.
  5. Ensure no user is listed as a result of the filter.

  **From Command Line:**
  To ensure IAM users are not assigned Service Account User role at the project level:

      gcloud projects get-iam-policy PROJECT_ID --format json | jq '.bindings[].role' | grep "roles/iam.serviceAccountUser"

      gcloud projects get-iam-policy PROJECT_ID --format json | jq '.bindings[].role' | grep "roles/iam.serviceAccountTokenCreator"

  These commands should not return any output.`,
  rationale: `A service account is a special Google account that belongs to an application or a virtual machine (VM), instead of to an individual end-user. Application/VM-Instance uses the service account to call the service's Google API so that users aren't directly involved. In addition to being an identity, a service account is a resource that has IAM policies attached to it. These policies determine who can use the service account.

  Users with IAM roles to update the App Engine and Compute Engine instances (such as App Engine Deployer or Compute Instance Admin) can effectively run code as the service accounts used to run these instances, and indirectly gain access to all the resources for which the service accounts have access. Similarly, SSH access to a Compute Engine instance may also provide the ability to execute code as that instance/Service account.

  Based on business needs, there could be multiple user-managed service accounts configured for a project. Granting the *iam.serviceAccountUser* or *iam.serviceAserviceAccountTokenCreatorccountUser* roles to a user for a project gives the user access to all service accounts in the project, including service accounts that may be created in the future. This can result in elevation of privileges by using service accounts and corresponding *Compute Engine instances*.

  In order to implement *least privileges* best practices, IAM users should not be assigned the *Service Account User* or *Service Account Token Creator* roles at the project level. Instead, these roles should be assigned to a user for a specific service account, giving that user access to the service account. The *Service Account User* allows a user to bind a service account to a long-running job service, whereas the *Service Account Token Creator* role allows a user to directly impersonate (or assert) the identity of a service account.`,
  remediation: `**From Console:**

  1. Go to the IAM page in the GCP Console by visiting: https://console.cloud.google.com/iam-admin/iam.
  2. Click on the filter table text bar. Type *Role: Service Account User*
  3. Click the *Delete Bin* icon in front of the role *Service Account User* for every user listed as a result of a filter.
  4. Click on the filter table text bar. Type *Role: Service Account Token Creator*
  5. Click the *Delete Bin* icon in front of the role *Service Account Token Creator* for every user listed as a result of a filter.

  **From Command Line:**

  1. Using a text editor, remove the bindings with the *roles/iam.serviceAccountUser* or *roles/iam.serviceAccountTokenCreator*.

  For example, you can use the iam.json file shown below as follows:

      {
      "bindings": [
          {
          "members": ["serviceAccount:our-project-123@appspot.gserviceaccount.com"],
          "role": "roles/appengine.appViewer"
          },
          {
          "members": ["user:email1@gmail.com"],
          "role": "roles/owner"
          },
          {
          "members": [
              "serviceAccount:our-project-123@appspot.gserviceaccount.com",
              "serviceAccount:123456789012-compute@developer.gserviceaccount.com"
          ],
          "role": "roles/editor"
          }
      ],
      "etag": "BwUjMhCsNvY="
      }

  2. Update the project's IAM policy:

          gcloud projects set-iam-policy PROJECT_ID iam.json`,
  references: [
    'https://cloud.google.com/iam/docs/service-accounts',
    'https://cloud.google.com/iam/docs/granting-roles-to-service-accounts',
    'https://cloud.google.com/iam/docs/understanding-roles',
    'https://cloud.google.com/iam/docs/granting-changing-revoking-access',
    'https://console.cloud.google.com/iam-admin/iam',
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
                'roles/iam.serviceAccountUser',
                'roles/iam.serviceAccountTokenCreator',
              ],
            },
          ],
        },
      },
    },
  },
}
