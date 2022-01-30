export default {
  id: 'gcp-cis-1.2.0-6.6',
  description:
    'GCP CIS 6.6 Ensure that Cloud SQL database instances do not have public IPs',
  audit: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console: https://console.cloud.google.com/sql/instances
  2. Ensure that every instance has a private IP address and no public IP address configured.
  
  **From Command Line:**
  
  1. List all Cloud SQL database instances using the following command:
  
          gcloud sql instances list
  
  2. For every instance of type *instanceType: CLOUD_SQL_INSTANCE* with *backendType: SECOND_GEN*, get detailed configuration. Ignore instances of type *READ_REPLICA_INSTANCE* because these instances inherit their settings from the primary instance. Also, note that first generation instances cannot be configured to have a private IP address.
  
          gcloud sql instances describe INSTANCE_NAME
  
  3. Ensure that the setting *ipAddresses* has an IP address configured of *type: PRIVATE* and has no IP address of type: PRIMARY. PRIMARY email addresses are public addresses. An instance can have both a private and public address at the same time. Note also that you cannot use private IP with First Generation instances.`,
  rationale: `To lower the organization's attack surface, Cloud SQL databases should not have public IPs. Private IPs provide improved network security and lower latency for your application.`,
  remediation: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console: https://console.cloud.google.com/sql/instances
  2. Click the instance name to open its Instance details page.
  3. Select the *Connections* tab.
  4. Deselect the *Public IP* checkbox.
  5. Click *Save* to update the instance.
  
  **From Command Line:**
  
  1. For every instance remove its public IP and assign a private IP instead:
  
          gcloud beta sql instances patch INSTANCE_NAME --network=VPC_NETWOR_NAME --no-assign-ip
  
  2. Confirm the changes using the following command::
  
          gcloud sql instances describe INSTANCE_NAME
  
  **Prevention:**
  
  To prevent new SQL instances from getting configured with public IP addresses, set up a *Restrict Public IP access on Cloud SQL instances* Organization policy at: https://console.cloud.google.com/iam-admin/orgpolicies/sql-restrictPublicIp.`,
  references: [
    `https://cloud.google.com/sql/docs/mysql/configure-private-ip`,
    `https://cloud.google.com/sql/docs/mysql/private-ip`,
    `https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
    `https://console.cloud.google.com/iam-admin/orgpolicies/sql-restrictPublicIp`,
  ],
  gql: `{
    querygcpSqlInstance(filter:{instanceType:{eq: "CLOUD_SQL_INSTANCE"}, backendType:{eq: "SECOND_GEN"}}) {
      id
      __typename
      name
      ipAddresses{
        type
      }
    }
  }`,
  resource: 'querygcpSqlInstance[*]',
  severity: 'unknown',
  conditions: {
    path: '@.ipAddresses',
    array_all: {
      path: '[*].type',
      equal: 'PRIVATE',
    },
  },
}
