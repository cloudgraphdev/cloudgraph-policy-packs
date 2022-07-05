/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
/* eslint-disable @typescript-eslint/no-explicit-any */
// GCP CIS 1.2.0 Rule equivalent 4.3
export default {
  id: 'gcp-pci-dss-3.2.1-vm-check-1',
  title: 'VM Check 1: Compute instance "block-project-ssh-keys" should be enabled',
  description: `It is recommended to use Instance specific SSH key(s) instead of using common/shared
  project-wide SSH key(s) to access Instances.`,
  audit: `**From Console:**

  1. Go to the *VM instances* page by visiting https://console.cloud.google.com/compute/instances. It will list all the instances in your project.
  2. For every instance, click on the name of the instance.
  3. Under *SSH Keys*, ensure *Block project-wide SSH keys* is selected.

  **From Command Line:**

  1. List all instances in a project:

          gcloud compute instances list

  2. For every instance, get the instance metadata:

          gcloud compute instances describe INSTANCE_NAME

  3. Ensure key: *block-project-ssh-keys* set to *value*: '*true*'.

  **Exception:**
  Instances created by GKE should be excluded. These instances have names that start with
  "gke-" and are labeled "goog-gke-node".`,
  rationale: 'Project-wide SSH keys are stored in Compute/Project-meta-data. Project wide SSH keys can be used to login into all the instances within project. Using project-wide SSH keys eases the SSH key management but if compromised, poses the security risk which can impact all the instances within project. It is recommended to use Instance specific SSH keys which can limit the attack surface if the SSH keys are compromised.',
  remediation: `**From Console:**

  1. Go to the *VM instances* page by visiting: https://console.cloud.google.com/compute/instances. It will list all the instances in your project.
  2. Click on the name of the Impacted instance
  3. Click *Edit* in the toolbar
  4. Under SSH Keys, go to the *Block project-wide SSH keys* checkbox
  5. To block users with project-wide SSH keys from connecting to this instance, select *Block project-wide SSH keys*
  6. Click *Save* at the bottom of the page
  7. Repeat steps for every impacted Instance

  **From Command Line:**
  Block project-wide public SSH keys, set the metadata value to *TRUE*:

      gcloud compute instances add-metadata INSTANCE_NAME --metadata block-project- ssh-keys=TRUE`,
  references: [
    'https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys',
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
      metadata{
        items{
          key
          value
        }
      }
    }
  }`,
  resource: 'querygcpVmInstance[*]',
  severity: 'medium',
  check: ({ resource }: any): boolean =>
    (/^gke-.*$/.test(resource.name) &&
      resource.labels?.some((l: any) => l.value === 'goog-gke-node')) ||
    !resource.metadata?.items ||
    resource.metadata?.items?.length === 0 ||
    (!(
      resource.project.length &&
      resource.serviceAccounts.length &&
      resource.serviceAccounts.some(
        (sa: any) =>
          sa.email ===
          `${
            resource.project[0].id.split('/')[1]
          }-compute@developer.gserviceaccount.com`
      )
    ) &&
      resource.metadata?.items?.some(
        (item: any) =>
          item.key === 'block-project-ssh-keys' && item.value === 'true'
      )),
}