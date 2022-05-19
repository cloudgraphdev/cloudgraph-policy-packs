//GCP CIS 1.2.0 Rule equivalent 1.5
export default {
  id: 'gcp-pci-dss-3.2.1-5.1',
  title: 'User-managed service accounts should not have admin privileges',
  description: `A service account is a special Google account that belongs to an application or a VM, instead
  of to an individual end-user. The application uses the service account to call the service's
  Google API so that users aren't directly involved. It's recommended not to use admin access
  for ServiceAccount.`,
  audit: `**From Console:**

  1. Go to _IAM & admin/IAM_ using https://console.cloud.google.com/iam-admin/iam
  2. Go to the _Members_
  3. Ensure that there are no _User-Managed user created service account(s)_ with roles containing _\*Admin_ or _\*admin_ or role matching _Editor_ or role matching _Owner_

  **From Command Line:**

  1. Get the policy that you want to modify, and write it to a JSON file: gcloud projects get-iam-policy PROJECT_ID --format json > iam.json
  2. The contents of the JSON file will look similar to the following. Note that _role_ of members group associated with each _serviceaccount_ does not contain *Admin or *admin or does not match _roles/editor_ or does not match _roles/owner_. This recommendation is only applicable to _User-Managed user-created_ service accounts. These accounts have the nomenclature: *SERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com*. Note that some Google- managed, Google-created service accounts have the same naming format, and should be excluded (e.g., *appsdev-apps-dev-script-auth@system.gserviceaccount.com* which needs the Owner role).

  **Sample Json output:**

      {
       "bindings": [
      {
        "members": ['serviceAccount:our-project-123@appspot.gserviceaccount.com'],
        "role": 'roles/appengine.appAdmin',
      },
      {
        "members": ['user:email1@gmail.com'],
        "role": 'roles/owner',
      },
      {
        "members": [
          'serviceAccount:our-project-123@appspot.gserviceaccount.com',
          'serviceAccount:123456789012-compute@developer.gserviceaccount.com',
        ],
        "role": 'roles/editor',
      },
      ],
        "etag": 'BwUjMhCsNvY=',
        "version": 1,
      }`,
  rationale: `Service accounts represent service-level security of the Resources (application or a VM) which can be determined by the roles assigned to them. Enrolling ServiceAccount with Admin rights gives full access to an assigned application or a VM. A ServiceAccount Access holder can perform critical actions like delete, update change settings, etc. without user intervention. For this reason, it's recommended that service accounts not have Admin rights.`,
  remediation: `**From Console**

  1. Go to *IAM & admin/IAM* using https://console.cloud.google.com/iam-admin/iam
  2. Go to the *Members*
  3. Identify *User-Managed user created* service account with roles containing *\*Admin* or *\*admin* or role matching *Editor* or role matching *Owner*
  4. Click the Delete *bin icon* to remove the role from the member (service account in this case)

  **From Command Line:**
  gcloud projects get-iam-policy PROJECT_ID --format json > iam.json

  1. Using a text editor, Remove *Role* which contains *roles/\*Admin* or *roles/\*admin* or matched *roles/editor* or matches *roles/owner*. Add a role to the bindings array that defines the group members and the role for those members.

  For example, to grant the role roles/appengine.appViewer to the *ServiceAccount* which is roles/editor, you would change the example shown below as follows:

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
    `https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/`,
    `https://cloud.google.com/iam/docs/understanding-roles`,
    `https://cloud.google.com/iam/docs/understanding-service-accounts`,
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
              match: /serviceAccount.*$/,
            },
            {
              or: [
                {
                  path: '[*].role',
                  in: ['roles/editor', 'roles/owner'],
                },
                {
                  path: '[*].role',
                  match: /admin.*$/gim,
                },
              ],
            },
          ],
        },
      },
    },
  },
}