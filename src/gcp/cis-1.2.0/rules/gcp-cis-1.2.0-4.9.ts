export default {
  id: 'gcp-cis-1.2.0-4.9',
  title:
    'GCP CIS 4.9 Ensure that Compute instances do not have public IP addresses',
  description:
    'Compute instances should not be configured to have external IP addresses.',
  audit: `**From Console:**

  1. Go to the *VM instances* page by visiting: https://console.cloud.google.com/compute/instances.
  2. For every VM, ensure that there is no *External IP* configured.

  **From Command Line:**

  1. List the instances in your project:

          gcloud compute instances list

  2. For every instance, list its configuration:

          gcloud compute instances describe INSTANCE_NAME --zone=ZONE

  3. The output should not contain an *accessConfigs* section under *networkInterfaces*. Note that the *natIP* value is present only for instances that are running or for instances that are stoped but have a static IP address. For instances that are stopped and are configured to have an ephemeral public IP address, the *natIP* field will not be present. Example output:

          networkInterfaces:
          - accessConfigs:
              - kind: compute#accessConfig
              name: External NAT
              networkTier: STANDARD
              type: ONE_TO_ONE_NAT

  **Exception:**

  Instances created by GKE should be excluded because some of them have external IP
  addresses and cannot be changed by editing the instance settings. Instances created by GKE
  should be excluded. These instances have names that start with "gke-" and are labeled
  "goog-gke-node".`,
  rationale: `To reduce your attack surface, Compute instances should not have public IP addresses. Instead, instances should be configured behind load balancers, to minimize the instance's exposure to the internet.`,
  remediation: `**From Console:**

  1. Go to the *VM instances* page by visiting: https://console.cloud.google.com/compute/instances.
  2. Click on the instance name to go the the *Instance detail page*.
  3. Click *Edit*.
  4. For each Network interface, ensure that *External IP* is set to *None*.
  5. Click *Done* and then click *Save*.

  **From Command Line:**

  1. Describe the instance properties:

          gcloud compute instances describe INSTANCE_NAME --zone=ZONE

  2. Identify the access config name that contains the external IP address. This access config appears in the following format:

          networkInterfaces:
          - accessConfigs:
              - kind: compute#accessConfig
              name: External NAT
              natIP: 130.211.181.55
              type: ONE_TO_ONE_NAT

  2. Delete the access config.

          gcloud compute instances delete-access-config INSTANCE_NAME --zone=ZONE -- access-config-name "ACCESS_CONFIG_NAME"


  In the above example, the *ACCESS_CONFIG_NAME* is *External NAT*. The name of your access
  config might be different.

  **Prevention:**

  You can configure the *Define allowed external IPs for VM instances* Organization Policy to prevent VMs from being configured with public IP addresses. Learn more at: https://console.cloud.google.com/orgpolicies/compute-vmExternalIpAccess`,
  references: [
    `https://cloud.google.com/load-balancing/docs/backend-service#backends_and_external_ip_addresses`,
    `https://cloud.google.com/compute/docs/instances/connecting-advanced#sshbetweeninstances`,
    `https://cloud.google.com/compute/docs/instances/connecting-to-instance`,
    `https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address#unassign_ip`,
    `https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints`,
  ],
  gql: `{
    querygcpVmInstance {
      id
      __typename
      name
      networkInterfaces {
        accessConfigs {
          name
          natIP
        }
      }
    }
  }`,
  resource: 'querygcpVmInstance[*]',
  severity: 'unknown',
  conditions: {
    not: {
      and: [
        {
          path: '@.name',
          mismatch: /^gke-.*$/,
        },
        {
          path: '@.networkInterfaces',
          array_any: {
            path: '[*].accessConfigs',
            array_any: {
              and: [
                {
                  path: '[*].natIP',
                  notEqual: null,
                },
                {
                  path: '[*].natIP',
                  notEqual: '',
                },
              ],
            },
          },
        },
      ],
    },
  },
}
