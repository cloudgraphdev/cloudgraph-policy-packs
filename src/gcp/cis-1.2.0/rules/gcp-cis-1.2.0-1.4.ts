export default {
  id: 'gcp-cis-1.2.0-1.4',
  title:
    'GCP CIS 1.4 Ensure that there are only GCP-managed service account keys for each service account',
  description:
    'User managed service accounts should not have user-managed keys.',
  audit: `**From Console:**

  1. Go to the IAM page in the GCP Console using https://console.cloud.google.com/iam-admin/iam

  2. In the left navigation pane, click Service accounts. All service accounts and their corresponding keys are listed.

  3. Click the service accounts and check if keys exist.

  **From Command Line:**

  List All the service accounts:

      gcloud iam service-accounts list

  Identify user-managed service accounts as such account EMAIL ends with iam.gserviceaccount.com

  For each user-managed service account, list the keys managed by the user:

      gcloud iam service-accounts keys list --iam-account= --managed-by=user

  No keys should be listed.`,

  rationale: `Anyone who has access to the keys will be able to access resources through the service
  account. GCP-managed keys are used by Cloud Platform services such as App Engine and
  Compute Engine. These keys cannot be downloaded. Google will keep the keys and
  automatically rotate them on an approximately weekly basis. User-managed keys are
  created, downloadable, and managed by users. They expire 10 years from creation.

  For user-managed keys, the user has to take ownership of key management activities
  which include:

  - Key storage
  - Key distribution
  - Key revocation
  - Key rotation
  - Protecting the keys from unauthorized users
  - Key recovery

  Even with key owner precautions, keys can be easily leaked by common development
  malpractices like checking keys into the source code or leaving them in the Downloads
  directory, or accidentally leaving them on support blogs/channels.

  It is recommended to prevent user-managed service account keys.`,

  remediation: `**From Console:**

  1. Go to the IAM page in the GCP Console using https://console.cloud.google.com/iam-admin/iam.

  2. In the left navigation pane, click Service accounts. All service accounts and their corresponding keys are listed.

  3. Click the service account.

  4. Click the edit and delete the keys.

  **From Command Line:**

  To delete a user managed Service Account Key,

      gcloud iam service-accounts keys delete --iam-account=<user-managed-service-account-EMAIL> <KEY-ID>`,

  references: [
    'https://cloud.google.com/iam/docs/understanding-service-accounts#managing_service_account_keys',
    'https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts',
  ],
  gql: `{
    querygcpServiceAccount {
      id
      __typename
      email
      keys {
        keyType
      }
    }
  }`,
  resource: 'querygcpServiceAccount[*]',
  severity: 'unknown',
  conditions: {
    not: {
      and: [
        {
          path: '@.email',
          match: /\s*iam.gserviceaccount.com/,
        },
        {
          path: '@.keys',
          array_any: {
            path: '[*].keyType',
            equal: 'USER_MANAGED',
          },
        },
      ],
    },
  },
}
