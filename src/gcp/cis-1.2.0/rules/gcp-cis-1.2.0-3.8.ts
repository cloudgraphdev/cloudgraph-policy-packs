export default {
  id: 'gcp-cis-1.2.0-3.8',
  title:
    'GCP CIS 3.8 Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network',
  description: `Flow Logs is a feature that enables users to capture information about the IP traffic going to
  and from network interfaces in the organization's VPC Subnets. Once a flow log is created,
  the user can view and retrieve its data in Stackdriver Logging. It is recommended that Flow
  Logs be enabled for every business-critical VPC subnet.`,

  audit: `**From Console:**

  1. Go to the VPC network GCP Console visiting https://console.cloud.google.com/networking/networks/list
  2. From the list of network subnets,
      make sure for each subnet *Flow Logs* is set to *On*

  **From Command Line:**

      gcloud compute networks list --format json | \ jq -r '.[].subnetworks | .[]' | \
      xargs -I {} gcloud compute networks subnets describe {} --format json | \
      jq -r '. | "Subnet: \(.name) Purpose: \(.purpose) VPC Flow Log Enabled: \(has("enableFlowLogs"))"'

  The output of the above command will list each subnet, the subnet's purpose, and a *true* or *false* value if *Flow Logs* are enabled.
  If the subnet's purpose is *PRIVATE* then *Flow Logs* should be *true*.
  `,
  rationale: `VPC networks and subnetworks not reserved for internal HTTP(S) load balancing provide logically isolated and secure network partitions where GCP resources can be launched. When Flow Logs are enabled for a subnet, VMs within that subnet start reporting on all Transmission Control Protocol (TCP) and User Datagram Protocol (UDP) flows. Each VM samples the TCP and UDP flows it sees, inbound and outbound, whether the flow is to or from another VM, a host in the on-premises datacenter, a Google service, or a host on the Internet. If two GCP VMs are communicating, and both are in subnets that have VPC Flow Logs enabled, both VMs report the flows.

  Flow Logs supports the following use cases:

  - Network monitoring
  - Understanding network usage and optimizing network traffic expenses
  - Network forensics
  - Real-time security analysis

  Flow Logs provide visibility into network traffic for each VM inside the subnet and can be used to detect
  anomalous traffic or provide insight during security workflows.

  Note: Subnets reserved for use by internal HTTP(S) load balancers do not support VPC flow logs.`,
  remediation: `**From Console:**

  1. Go to the VPC network GCP Console visiting https://console.cloud.google.com/networking/networks/list
  2. Click the name of a subnet, The *Subnet details* page displays.
  3. Click the *EDIT* button.
  4. Set *Flow Logs* to *On*.
  5. Click Save.

  **From Command Line:**
  To set Private Google access for a network subnet, run the following command:

      gcloud compute networks subnets update [SUBNET_NAME] --region [REGION] --enable-flow-logs`,
  references: [
    `https://cloud.google.com/vpc/docs/using-flow-logs#enabling_vpc_flow_logging`,
    `https://cloud.google.com/vpc/`,
  ],
  gql: `{
    querygcpNetwork{
      id
      __typename
      subnet{
        purpose
        enableFlowLogs
      }
    }
  }`,
  resource: 'querygcpNetwork[*]',
  severity: 'high',
  conditions: {
    path: '@.subnet',
    array_all: {
      or: [
        {
          path: '[*].purpose',
          notEqual: 'PRIVATE',
        },
        {
          and: [
            {
              path: '[*].purpose',
              equal: 'PRIVATE',
            },
            {
              path: '[*].enableFlowLogs',
              equal: true,
            },
          ],
        },
      ],
    },
  },
}
