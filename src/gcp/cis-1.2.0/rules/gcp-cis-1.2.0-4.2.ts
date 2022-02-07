export default {
  id: 'gcp-cis-1.2.0-4.2',
  title:
    'GCP CIS 4.2 Ensure that instances are not configured to use the default service account with full access to all Cloud APIs',
  description: `To support principle of least privileges and prevent potential privilege escalation it is
  recommended that instances are not assigned to default service account Compute Engine
  default service account with Scope Allow full access to all Cloud APIs.`,
  audit: `**From Console:**

  1. Go to the *VM instances* page by visiting: https://console.cloud.google.com/compute/instances.
  2. Click on each instance name to go to its *VM instance details* page.
  3. If the *Default Compute Engine service account* is selected under *Service Account*, ensure that *Cloud API access scopes* is not set to *Allow full access to all Cloud APIs*.

  **From Command Line:**

  1. List Instances from project

          gcloud compute instances list

  2. Get the details on each instance:

          gcloud compute instances describe INSTANCE_NAME --zone ZONE

  3. Ensure that the instance is not configured to allow the https://www.googleapis.com/auth/cloud-platform scope for the default Compute Engine service account:

          serviceAccounts:
          - email: [PROJECT_NUMBER]-compute@developer.gserviceaccount.com
          scopes:
          - https://www.googleapis.com/auth/cloud-platform

  **Exception:** Instances created by GKE should be excluded. These instances have names that
  start with "gke-" and are labeled "goog-gke-node"`,
  rationale: `Along with ability to optionally create, manage and use user managed custom service accounts, Google Compute Engine provides default service account *Compute Engine default service account* for an instances to access necessary cloud services. *Project Editor* role is assigned to *Compute Engine default service account* hence, This service account has almost all capabilities over all cloud services except billing. However, when *Compute Engine default service account* assigned to an instance it can operate in 3 scopes.

  1. Allow default access: Allows only minimum access required to run an Instance (Least Privileges)
  2. Allow full access to all Cloud APIs: Allow full access to all the cloud APIs/Services (Too much access)
  3. Set access for each API: Allows Instance administrator to choose only those APIs that are needed to perform specific business functionality expected by instance

  When an instance is configured with *Compute Engine default service account* with Scope *Allow full access to all Cloud APIs*, based on IAM roles assigned to the user(s) accessing Instance, it may allow user to perform cloud operations/API calls that user is not supposed to perform leading to successful privilege escalation.`,
  remediation: `**From Console:**

  1. Go to the *VM instances* page by visiting: https://console.cloud.google.com/compute/instances.
  2. Click on the impacted VM instance.
  3. If the instance is not stopped, click the *Stop* button. Wait for the instance to be stopped.
  4. Next, click the *Edit* button.
  5. Scroll down to the *Service Account* section.
  6. Select a different service account or ensure that *Allow full access to all Cloud APIs* is not selected.
  7. Click the *Save* button to save your changes and then click *START*.

  **From Command Line:**

  1. Stop the instance:

          gcloud compute instances stop INSTANCE_NAME

  2. Update the instance:

          gcloud compute instances set-service-account INSTANCE_NAME --service- account=SERVICE_ACCOUNT --scopes [SCOPE1, SCOPE2...]

  3. Restart the instance:

          gcloud compute instances start INSTANCE_NAME`,
  references: [
    `https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances`,
    `https://cloud.google.com/compute/docs/access/service-accounts`,
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
        scopes
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
        | {"match" : (length > 0), "scopes": .[].scopes} // {"match" : false, "scopes": []}`,
        path: '@',
        and: [
          {
            path: '@.match',
            notEqual: true,
          },
          {
            path: '[*].scopes',
            array_all: {
              notEqual: 'https://www.googleapis.com/auth/cloud-platform',
            },
          },
        ],
      },
    ],
  },
}
