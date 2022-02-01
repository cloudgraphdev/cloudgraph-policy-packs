export default {
  id: 'gcp-cis-1.2.0-5.1',
  description:
    'GCP CIS 5.1 Ensure that Cloud Storage bucket is not anonymously or publicly accessible',
  audit: `**From Console:**

  1. Go to Storage browser by visiting
      https://console.cloud.google.com/storage/browser.
  2. Click on each bucket name to go to its Bucket details page.
  3. Click on the Permissions tab.
  4. Ensure that allUsers and allAuthenticatedUsers are not in the Members list.

  **From Command Line:**

  1. List all buckets in a project

          gsutil ls

  2. Check the IAM Policy for each bucket:

          gsutil iam get gs://BUCKET_NAME


  No role should contain allUsers and/or allAuthenticatedUsers as a member.

  **Using Rest API**

  1. List all buckets in a project

          Get https://www.googleapis.com/storage/v1/b?project=<ProjectName>

  2. Check the IAM Policy for each bucket

          GET https://www.googleapis.com/storage/v1/b/<bucketName>/iam

  No role should contain allUsers and/or allAuthenticatedUsers as a member.`,
  rationale: `Allowing anonymous or public access grants permissions to anyone to access bucket
  content. Such access might not be desired if you are storing any sensitive data. Hence,
  ensure that anonymous or public access to a bucket is not allowed.`,
  remediation: `**From Console:**

  1. Go to Storage browser by visiting
      https://console.cloud.google.com/storage/browser.
  2. Click on the bucket name to go to its Bucket details page.
  3. Click on the Permissions tab.
  4. Click Delete button in front of allUsers and allAuthenticatedUsers to remove
      that particular role assignment.

  **From Command Line:**
  Remove allUsers and allAuthenticatedUsers access.

      gsutil iam ch -d allUsers gs://BUCKET_NAME
      gsutil iam ch -d allAuthenticatedUsers gs://BUCKET_NAME

  **Prevention:**
  You can prevent Storage buckets from becoming publicly accessible by setting up the
  Domain restricted sharing organization policy at:
  https://console.cloud.google.com/iam-admin/orgpolicies/iam-
  allowedPolicyMemberDomains.

  **Default Value:**

  By Default, Storage buckets are not publicly shared.`,
  references: [
    'https://cloud.google.com/storage/docs/access-control/iam-reference',
    'https://cloud.google.com/storage/docs/access-control/making-data-public',
    'https://cloud.google.com/storage/docs/gsutil/commands/iam',
  ],
  gql: `{
    querygcpStorageBucket {
      id
      __typename
      iamPolicy {
        bindings {
          role
          members
        }
      }
    }
  }`,
  resource: 'querygcpStorageBucket[*]',
  severity: 'unknown',
  conditions: {
    not: {
      path: '@.iamPolicy',
      array_any: {
        path: '[*].bindings',
        array_any: {
          path: '[*].members',
          array_any: {
            path: '[*]',
            in: ['allUsers', 'allAuthenticatedUsers'],
          },
        },
      },
    },
  },
}
