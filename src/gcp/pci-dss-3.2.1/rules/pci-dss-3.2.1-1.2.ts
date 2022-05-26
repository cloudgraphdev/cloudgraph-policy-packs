//GCP CIS 1.2.0 Rule equivalent 4.5
export default {
  id: 'gcp-pci-dss-3.2.1-1.2',
  title: 'Compute instances "Enable connecting to serial ports" should not be enabled',
  description: `Interacting with a serial port is often referred to as the serial console, which is similar to
  using a terminal window, in that input and output is entirely in text mode and there is no
  graphical interface or mouse support.

  If you enable the interactive serial console on an instance, clients can attempt to connect to
  that instance from any IP address. Therefore interactive serial console support should be
  disabled.`,
  audit: `**From Console:**

  1. Login to Google Cloud console
  2. Go to Computer Engine
  3. Go to VM instances
  4. Click on the Specific VM
  5. Ensure *Enable connecting to serial ports* below *Remote access* block is
      unselected.

  **From Command Line:**
  Ensure the below command's output shows *null*:

      gcloud compute instances describe <vmName> --zone=<region> -- format="json(metadata.items[].key,metadata.items[].value)"

  or *key* and *value* properties from below command's json response are equal to *serial-port-enable* and *0* or *false* respectively.

      {
      "metadata": {
          "items": [
          {
              "key": "serial-port-enable",
              "value": "0"
          }
          ]
        }
      }`,
  rationale: `A virtual machine instance has four virtual serial ports. Interacting with a serial port is similar to using a terminal window, in that input and output is entirely in text mode and there is no graphical interface or mouse support. The instance's operating system, BIOS, and other system-level entities often write output to the serial ports, and can accept input such as commands or answers to prompts. Typically, these system-level entities use the first serial port (port 1) and serial port 1 is often referred to as the serial console.

  The interactive serial console does not support IP-based access restrictions such as IP whitelists. If you enable the interactive serial console on an instance, clients can attempt to connect to that instance from any IP address. This allows anybody to connect to that instance if they know the correct SSH key, username, project ID, zone, and instance name.

  Therefore interactive serial console support should be disabled.`,
  remediation: `**From Console:**

  1. Login to Google Cloud console
  2. Go to Computer Engine
  3. Go to VM instances
  4. Click on the Specific VM
  5. Click *EDIT*
  6. Unselect *Enable connecting to serial ports* below *Remote access* block.
  7. Click *Save*

  **From Command Line:**
  Use the below command to disable

      gcloud compute instances add-metadata INSTANCE_NAME --zone=ZONE -- metadata=serial-port-enable=false

  or

      gcloud compute instances add-metadata INSTANCE_NAME --zone=ZONE -- metadata=serial-port-enable=0

  **Prevention:**
  You can prevent VMs from having serial port access enable by *Disable VM serial port
  access* organization policy: https://console.cloud.google.com/iam-admin/orgpolicies/compute-disableSerialPortAccess.`,
  references: [
    `https://cloud.google.com/compute/docs/instances/interacting-with-serial-console`,
  ],
  gql: `{
    querygcpVmInstance{
      __typename
      id
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
  conditions: {
    path: '@.metadata.items',
    array_any: {
      or: [
        {
          and: [
            {
              path: '[*].key',
              equal: 'serial-port-enable',
            },
            {
              path: '[*].value',
              equal: '0',
            },
          ],
        },
        {
          and: [
            {
              path: '[*].key',
              equal: 'serial-port-enable',
            },
            {
              path: '[*].value',
              equal: 'false',
            },
          ],
        },
      ],
    },
  },
}