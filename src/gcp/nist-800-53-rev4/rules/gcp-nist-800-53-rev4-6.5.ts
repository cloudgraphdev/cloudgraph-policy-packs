// GCP CIS 1.2.0 Rule equivalent 4.6
export default {
  id: 'gcp-nist-800-53-rev4-6.5',
  title: 'GCP NIST 6.5 Compute instances "IP forwarding" should not be enabled',
  description: `Compute Engine instance cannot forward a packet unless the source IP address of the
  packet matches the IP address of the instance. Similarly, GCP won't deliver a packet whose
  destination IP address is different than the IP address of the instance receiving the packet.
  However, both capabilities are required if you want to use instances to help route packets.

  Forwarding of data packets should be disabled to prevent data loss or information
  disclosure.`,
  audit: `**From Console:**

  1. Go to the *VM Instances* page by visiting: https://pantheon.corp.google.com/compute/instances.
  2. For every instance, click on its name to go to the *VM instance details* page.
  3. Under the Network interfaces section, ensure that *IP forwarding* is set to *Off* for every network interface.

  **From Command Line:**

  1. List all instances:

          gcloud compute instances list --format='table(name,canIpForward)'

  2. Ensure that *CAN_IP_FORWARD* column in the output of above command does not contain *True* for any VM instance.

  **Exception:**
  Instances created by GKE should be excluded because they need to have IP forwarding enabled and cannot be changed. Instances created by GKE have names that start with "gke-".`,
  rationale: 'Compute Engine instance cannot forward a packet unless the source IP address of the packet matches the IP address of the instance. Similarly, GCP won\'t deliver a packet whose destination IP address is different than the IP address of the instance receiving the packet. However, both capabilities are required if you want to use instances to help route packets. To enable this source and destination IP check, disable the canIpForward field, which allows an instance to send and receive packets with non-matching destination or source IPs.',
  remediation: `**Note:** You only edit the *canIpForward* setting at instance creation time. Therefore, you need to
  delete the instance and create a new one where *canIpForward* is set to *false*.

  **From Console:**

  1. Go to the *VM Instances* page by visiting: https://pantheon.corp.google.com/compute/instances.
  2. Select the *VM Instance* you want to remediate.
  3. Click the *Delete* button.
  4. On the 'VM Instances' page, click 'CREATE INSTANCE'.
  5. Create a new instance with the desired configuration. By default, the instance is configured to not allow IP forwarding.

  **From Command Line:**

  1. Delete the instance:

          gcloud compute instances delete INSTANCE_NAME

  2. Create a new instance to replace it, with *IP forwarding* set to *Off*

          gcloud compute instances create`,
  references: ['https://cloud.google.com/vpc/docs/using-routes#canipforward'],
  gql: `{
    querygcpVmInstance{
      __typename
      id
      canIpForward
    }
  }`,
  resource: 'querygcpVmInstance[*]',
  severity: 'medium',
  conditions: {
    path: '@.canIpForward',
    equal: false,
  },
}
