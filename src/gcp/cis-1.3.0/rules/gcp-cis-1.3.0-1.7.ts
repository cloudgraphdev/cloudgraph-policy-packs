export default {
  id: 'gcp-cis-1.3.0-1.7',
  title:
    'GCP CIS 1.7 Ensure user-managed/external keys for service accounts are rotated every 90 days or less',
  description: `Service Account keys consist of a key ID (Private_key_Id) and Private key, which are used to
  sign programmatic requests users make to Google cloud services accessible to that
  particular service account. It is recommended that all Service Account keys are regularly
  rotated.`,
  audit: `**From Console:**

  1. Go to APIs & Services\\Credentials using https://console.cloud.google.com/apis/credentials

  2. In the section Service Account Keys, for every External (user-managed) service account key listed ensure the
  creation date is within the past 90 days.

  **From Command Line:**

  1. List all Service accounts from a project.

          gcloud iam service-accounts list

  2. For every service account list service account keys

          gcloud iam service-accounts keys list --iam-account[Service_Account_Email_Id] --format=json

  3. Ensure every service account key for a service account has a "validAfterTime" value within the past 90 days.`,

  rationale: `Rotating Service Account keys will reduce the window of opportunity for an access key that
  is associated with a compromised or terminated account to be used. Service Account keys
  should be rotated to ensure that data cannot be accessed with an old key that might have
  been lost, cracked, or stolen.

  Each service account is associated with a key pair managed by Google Cloud Platform
  (GCP). It is used for service-to-service authentication within GCP. Google rotates the keys
  daily.

  GCP provides the option to create one or more user-managed (also called external key
  pairs) key pairs for use from outside GCP (for example, for use with Application Default
  Credentials). When a new key pair is created, the user is required to download the private
  key (which is not retained by Google). With external keys, users are responsible for keeping
  the private key secure and other management operations such as key rotation. External
  keys can be managed by the IAM API, gcloud command-line tool, or the Service Accounts
  page in the Google Cloud Platform Console. GCP facilitates up to 10 external service account
  keys per service account to facilitate key rotation.`,

  remediation: `**From Console:**

  Delete any external (user-managed) Service Account Key older than 90 days:

  1. Go to APIs & Services\\Credentials using https://console.cloud.google.com/apis/credentials

  2. In the Section Service Account Keys, for every external (user-managed) service account key where creation date is greater than
  or equal to the past 90 days, click Delete Bin Icon to Delete Service Account key

  Create a new external (user-managed) Service Account Key for a Service Account:

  1. Go to APIs & Services\\Credentials using https://console.cloud.google.com/apis/credentials
  2. Click Create Credentials and Select Service Account Key.
  3. Choose the service account in the drop-down list for which an External (user-managed) Service Account key needs to be created.
  4. Select the desired key type format among JSON or P12.
  5. Click Create. It will download the private key. Keep it safe.
  6. Click Close if prompted.
  7. The site will redirect to the APIs & Services\\Credentials page. Make a note of the new ID displayed in the Service
  account keys section.`,

  references: [
    'https://cloud.google.com/iam/docs/understanding-service-accounts#managing_service_account_keys',
    'https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/keys/list',
    'https://cloud.google.com/iam/docs/service-accounts',
  ],
  gql: `{
    querygcpServiceAccount {
      id
      __typename
      email
      keys {
        validAfterTime
      }
    }
  }`,
  resource: 'querygcpServiceAccount[*]',
  severity: 'unknown',
  conditions: {
    not: {
      path: '@.keys',
      array_any: {
        value: { daysAgo: {}, path: '[*].validAfterTime' },
        greaterThan: 90,
      },
    },
  },
}
