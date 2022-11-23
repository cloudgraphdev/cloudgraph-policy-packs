export default {
  id: 'gcp-cis-1.3.0-6.5',
  title:
    'GCP CIS 6.5 Ensure that Cloud SQL database instances are not open to the world',
  description: `Database Server should accept connections only from trusted Network(s)/IP(s) and
  restrict access from the world.`,
  audit: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Click the instance name to open its *Instance details* page.
  3. Under the *Configuration* section click *Edit configurations*.
  4. Under *Configuration options* expand the *Connectivity* section.
  5. Ensure that no authorized network is configured to allow *0.0.0.0/0*.

  **From Command Line:**

  1. List all Cloud SQL database Instances using the following command:

          gcloud sql instances list


  2. Get detailed configuration for every Cloud SQL database instance.

          gcloud sql instances describe INSTANCE_NAME

  Ensure that the section *settings: ipConfiguration : authorizedNetworks* does not have any parameter value containing *0.0.0.0/0*.`,
  rationale: `To minimize attack surface on a Database server instance, only trusted/known and required IP(s) should be white-listed to connect to it.

  An authorized network should not have IPs/networks configured to *0.0.0.0/0* which will allow access to the instance from anywhere in the world. Note that authorized networks apply only to instances with public IPs.`,
  remediation: `**From Console:**

  1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting https://console.cloud.google.com/sql/instances.
  2. Click the instance name to open its *Instance details* page.
  3. Under the *Configuration* section click *Edit configuration*s
  4. Under *Configuration options* expand the *Connectivity* section.
  5. Click the *delete* icon for the authorized network *0.0.0.0/0*.
  6. Click *Save* to update the instance.

  **From Command Line:**

  Update the authorized network list by dropping off any addresses.

          gcloud sql instances patch INSTANCE_NAME --authorized-networks=IP_ADDR1,IP_ADDR2...

  **Prevention:**

  To prevent new SQL instances from being configured to accept incoming connections from any IP addresses, set up a *Restrict Authorized Networks on Cloud SQL instances* Organization Policy at: https://console.cloud.google.com/iam-admin/orgpolicies/sql-restrictAuthorizedNetworks.`,
  references: [
    'https://cloud.google.com/sql/docs/mysql/configure-ip',
    'https://console.cloud.google.com/iam-admin/orgpolicies/sql-restrictAuthorizedNetworks',
    'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    'https://cloud.google.com/sql/docs/mysql/connection-org-policy',
  ],
  gql: `{
    querygcpSqlInstance {
      id
      __typename
      name
      settings {
        ipConfiguration {
          authorizedNetworks {
            value
          }
        }
      }
    }
  }`,
  resource: 'querygcpSqlInstance[*]',
  severity: 'high',
  conditions: {
    path: '@.settings.ipConfiguration.authorizedNetworks',
    array_all: {
      path: '[*].value',
      notEqual: '0.0.0.0/0',
    },
  },
}
