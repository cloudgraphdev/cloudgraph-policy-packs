// GCP CIS 1.2.0 Rule equivalent 3.1
export default {
  id: 'gcp-pci-dss-3.2.1-networking-check-3',  
  title:
    'Networking check 3: The default network for a project should be deleted',

  description:
    'To prevent use of default network, a project should not have a default network.',
  
  audit: `**From Console:**

  1. Go to the *VPC networks* page by visiting: https://console.cloud.google.com/networking/networks/list.
  2. Ensure that a network with the name *default* is not present.

  **From Command Line:**

  1. Set the project name in the Google Cloud Shell:

          gcloud config set project PROJECT_ID

  2. List the networks configured in that project:

          gcloud compute networks list

  It should not list *default* as one of the available networks in that project.`,

  rationale: `The *default* network has a preconfigured network configuration and automatically generates the following insecure firewall rules:

  - default-allow-internal: Allows ingress connections for all protocols and ports among instances in the network.
  - default-allow-ssh: Allows ingress connections on TCP port 22(SSH) from any source to any instance in the network.
  - default-allow-rdp: Allows ingress connections on TCP port 3389(RDP) from any source to any instance in the network.
  - default-allow-icmp: Allows ingress ICMP traffic from any source to any instance in the network.

  These automatically created firewall rules do not get audit logged and cannot be configured
  to enable firewall rule logging.

  Furthermore, the default network is an auto mode network, which means that its subnets
  use the same predefined range of IP addresses, and as a result, it's not possible to use Cloud
  VPN or VPC Network Peering with the default network.

  Based on organization security and networking requirements, the organization should
  create a new network and delete the *default* network.`,

  remediation: `**From Console:**

  1. Go to the *VPC networks* page by visiting: https://console.cloud.google.com/networking/networks/list.
  2. Click the network named *default*.
  3. On the network detail page, click *EDIT*.
  4. Click *DELETE VPC NETWORK*.
  5. If needed, create a new network to replace the default network.

  **From Command Line:**
  For each Google Cloud Platform project,

  1. Delete the default network:

          gcloud compute networks delete default

  2. If needed, create a new network to replace it:

          gcloud compute networks create NETWORK_NAME

  **Prevention:**
  The user can prevent the default network and its insecure default firewall rules from being created by setting up an Organization Policy to Skip default network creation at https://console.cloud.google.com/iam-admin/orgpolicies/compute-skipDefaultNetworkCreation.`,

  references: [
    'https://cloud.google.com/compute/docs/networking#firewall_rules',
    'https://cloud.google.com/compute/docs/reference/latest/networks/insert',
    'https://cloud.google.com/compute/docs/reference/latest/networks/delete',
    'https://cloud.google.com/vpc/docs/firewall-rules-logging',
    'https://cloud.google.com/vpc/docs/vpc#default-network',
    'https://cloud.google.com/sdk/gcloud/reference/compute/networks/delete',
  ],
  gql: `{
    querygcpNetwork {
      id
      __typename
      name
    }
  }`,
  resource: 'querygcpNetwork[*]',
  severity: 'medium',
  conditions: {
    path: '@.name',
    notEqual: 'default',
  },
}
