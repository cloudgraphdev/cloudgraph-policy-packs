export default {
  id: 'gcp-cis-1.2.0-4.1',
  description:
    'GCP CIS 4.1 Ensure that instances are not configured to use the default service account',
  audit: `**From Console:**

  1. Go to the *VM instances* page by visiting: https://console.cloud.google.com/compute/instances.
  2. Click on each instance name to go to its *VM instance details* page.
  3. Under the section *Service Account*, ensure that the default Compute Engine service account is not used. This account is named *[PROJECT_NUMBER]-compute@developer.gserviceaccount.com*.
  
  **From Command Line:**
  
  1. List the instances in your project:
  
          gcloud compute instances list
  
  2. Get the details on each instance:
  
          gcloud compute instances describe INSTANCE_NAME --zone ZONE
  
  3. Ensure that the service account section does not have an email that matches the pattern used does not match the pattern *[PROJECT_NUMBER]-compute@developer.gserviceaccount.com*.
  
  **Exception:**  
  VMs created by GKE should be excluded. These VMs have names that start with *gke-* and
  are labeled *goog-gke-node*.`,
  rationale: `The default Compute Engine service account has the Editor role on the project, which allows read and write access to most Google Cloud Services. To defend against privilege escalations if your VM is compromised and prevent an attacker from gaining access to all of your project, it is recommended to not use the default Compute Engine service account. Instead, you should create a new service account and assigning only the permissions needed by your instance.

  The default Compute Engine service account is named *[PROJECT_NUMBER]- compute@developer.gserviceaccount.com*.`,
  remediation: `**From Console:**

  1. Go to the *VM instances* page by visiting:https://console.cloud.google.com/compute/instances.
  2. Click on the instance name to go to its *VM instance details* page.
  3. Click *STOP* and then click *EDIT*.
  4. Under the section *Service Account*, select a service account other than the default Compute Engine service account. You may first need to create a new service account.
  5. Click *Save* and then click *START*.
  
  **From Command Line:**
  
  1. Stop the instance:
  
          gcloud compute instances stop INSTANCE_NAME
  
  2. Update the instance:
  
          gcloud compute instances set-service-account INSTANCE_NAME --service-account=SERVICE_ACCOUNT
  
  3. Restart the instance:
  
          gcloud compute instances start INSTANCE_NAME`,
  references: [
    `https://cloud.google.com/compute/docs/access/service-accounts`,
    `https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances`,
    `https://cloud.google.com/sdk/gcloud/reference/compute/instances/set-service-account`,
  ],
  gql: `{
    querygcpVmInstance{
      __typename
      id
      project{
        id
      }
      name
      labels{
        value
      }
      serviceAccounts{
        email
      }
    }
  }`,
  resource: 'querygcpVmInstance[*]',
  severity: 'medium',
  conditions: {
    path: '@',
    or: [
      {
        path: '@',
        and: [
          {
            path: '[*].name',
            match: /^gke-.*$/,
          },
          {
            path: '[*].labels',
            array_any: {
              path: '[*].value',
              equal: 'goog-gke-node',
            },
          },
        ],
      },
      {
        jq: `[{ "defaultEmail" : (.project[].id | split("/") | .[1] + "-compute@developer.gserviceaccount.com")} + .serviceAccounts[]]
        | [.[] | select(.defaultEmail == .email) ]
        | {"match" : (length > 0)}`,
        path: '@',
        and: [
          {
            path: '@.match',
            notEqual: true,
          },
        ],
      },
    ],
  },
}
