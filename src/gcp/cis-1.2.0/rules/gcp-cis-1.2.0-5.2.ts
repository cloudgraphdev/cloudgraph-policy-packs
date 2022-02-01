export default {
  id: 'gcp-cis-1.2.0-5.2',
  description:
    'GCP CIS 5.2 Ensure that Cloud Storage buckets have uniform bucket-level access enabled',
  audit: `**From Console:**

  1. Open the Cloud Storage browser in the Google Cloud Console by visiting: https://console.cloud.google.com/storage/browser
  2. For each bucket, make sure that *Access control* column has the value *Uniform*.
  
  **From Command Line:**
  
  1. List all buckets in a project
  
          gsutil ls
  
  2. For each bucket, verify that uniform bucket-level access is enabled.
  
          gsutil uniformbucketlevelaccess get gs://BUCKET_NAME/
  
  If uniform bucket-level access is enabled, the response looks like:
  
      Uniform bucket-level access setting for gs://BUCKET_NAME/:
          Enabled: True
          LockedTime: LOCK_DATE`,
  rationale: `It is recommended to use uniform bucket-level access to unify and simplify how you grant access to your Cloud Storage resources.

  Cloud Storage offers two systems for granting users permission to access your buckets and objects: Cloud Identity and Access Management (Cloud IAM) and Access Control Lists (ACLs). These systems act in parallel - in order for a user to access a Cloud Storage resource, only one of the systems needs to grant the user permission. Cloud IAM is used throughout Google Cloud and allows you to grant a variety of permissions at the bucket and project levels. ACLs are used only by Cloud Storage and have limited permission options, but they allow you to grant permissions on a per-object basis.
  
  In order to support a uniform permissioning system, Cloud Storage has uniform bucket- level access. Using this feature disables ACLs for all Cloud Storage resources: access to Cloud Storage resources then is granted exclusively through Cloud IAM. Enabling uniform bucket-level access guarantees that if a Storage bucket is not publicly accessible, no object in the bucket is publicly accessible either.`,
  remediation: `**From Console:**

  1. Open the Cloud Storage browser in the Google Cloud Console by visiting: https://console.cloud.google.com/storage/browser
  2. In the list of buckets, click on the name of the desired bucket.
  3. Select the *Permissions* tab near the top of the page.
  4. In the text box that starts with *This bucket uses fine-grained access control...*, click *Edit*.
  5. In the pop-up menu that appears, select *Uniform*.
  6. Click *Save*.
  
  **From Command Line:**
  
  Use the on option in a uniformbucketlevelaccess set command:
  
      gsutil uniformbucketlevelaccess set on gs://BUCKET_NAME/
  
  **Prevention**
  You can set up an Organization Policy to enforce that any new bucket has uniform bucket level access enabled. Learn more at: https://cloud.google.com/storage/docs/setting-org-policies#uniform-bucket`,
  references: [
    `https://cloud.google.com/storage/docs/uniform-bucket-level-access`,
    `https://cloud.google.com/storage/docs/using-uniform-bucket-level-access`,
    `https://cloud.google.com/storage/docs/setting-org-policies#uniform-bucket`,
  ],
  gql: `{
    querygcpStorageBucket {
      __typename
      id
      iamConfiguration {
        uniformBucketLevelAccess {
          enabled
        }
      }
    }
  }`,
  resource: 'querygcpStorageBucket[*]',
  severity: 'high',
  conditions: {
    path: '@.iamConfiguration.uniformBucketLevelAccess.enabled',
    equal: true,
  },
}
