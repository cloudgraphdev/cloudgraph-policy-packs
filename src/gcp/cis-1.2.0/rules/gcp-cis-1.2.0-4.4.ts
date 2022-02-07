export default {
  id: 'gcp-cis-1.2.0-4.4',
  title: 'GCP CIS 4.4 Ensure oslogin is enabled for a Project',
  description: `Enabling OS login binds SSH certificates to IAM users and facilitates effective SSH certificate
  management.`,
  audit: `**From Console:**

  1. Go to the VM compute metadata page by visiting
      https://console.cloud.google.com/compute/metadata.
  2. Ensure that key enable-oslogin is present with value set to TRUE.
  3. Because instances can override project settings, ensure that no instance has custom
      metadata with key enable-oslogin and value FALSE.

  **From Command Line:**

  1. Ensure that OS login is enabled on the project:

          gcloud compute project-info describe

  2. Verify that the section commonInstanceMetadata has a key enable-oslogin set to
      value TRUE.
  3. Ensure that no instance in the project overrides the project setting:

          gcloud compute instances describe INSTANCE_NAME`,
  rationale: `Enabling osLogin ensures that SSH keys used to connect to instances are mapped with IAM
  users. Revoking access to IAM user will revoke all the SSH keys associated with that
  particular user. It facilitates centralized and automated SSH key pair management which is
  useful in handling cases like response to compromised SSH key pairs and/or revocation of
  external/third-party/Vendor users.`,
  remediation: `**From Console:**

  1. Go to the VM compute metadata page by visiting:
      https://console.cloud.google.com/compute/metadata.
  2. Click Edit.
  3. Add a metadata entry where the key is enable-oslogin and the value is TRUE.
  4. Click Save to apply the changes.
  5. For every instances that overrides the project setting, go to the VM Instances page
      at https://console.cloud.google.com/compute/instances.
  6. Click the name of the instance on which you want to remove the metadata value.
  7. At the top of the instance details page, click Edit to edit the instance settings.
  8. Under Custom metadata, remove any entry with key enable-oslogin and the value
      is FALSE
  9. At the bottom of the instance details page, click Save to apply your changes to the
      instance.

  **From Command Line:**

  1. Configure oslogin on the project:

          gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE

  2. Remove instance metadata that overrides the project setting.

          gcloud compute instances remove-metadata INSTANCE_NAME --keys=enable-oslogin

  Optionally, you can enable two factor authentication fir OS login. For more information,
  see: https://cloud.google.com/compute/docs/oslogin/setup-two-factor-authentication.

  **Default Value:**

  By default, parameter enable-oslogin is not set, which is equivalent to setting it to FALSE.`,
  references: [
    'https://cloud.google.com/compute/docs/instances/managing-instance-access',
    'https://cloud.google.com/compute/docs/instances/managing-instance-access#enable_oslogin',
    'https://cloud.google.com/sdk/gcloud/reference/compute/instances/remove-metadata',
    'https://cloud.google.com/compute/docs/oslogin/setup-two-factor-authentication',
  ],
  gql: `{
    querygcpProject {
      id
      __typename
      computeProject {
        commonInstanceMetadata {
          items {
            key
            value
          }
        }
      }
      vmInstance {
        metadata {
          items {
            key
            value
          }
        }
      }
    }
  }`,
  resource: 'querygcpProject[*]',
  severity: 'unknown',
  conditions: {
    path: '@',
    jq: '.  | [(.computeProject[].commonInstanceMetadata.items | map({"cimKey": .key, "cimValue": .value }))[] + ((.vmInstance[].metadata.items  | map({"vmiKey": .key, "vmiValue": .value}))[] // {"vmiKey": null, "vmiValue": null} )  | select(.cimKey == "enable-oslogin" and .cimValue == "true" )  ]',
    and: [
      {
        path: '@',
        isEmpty: false,
      },
      {
        path: '@',
        array_all: {
          or: [
            {
              and: [
                {
                  path: '[*].cimValue',
                  equal: 'true',
                },
                {
                  path: '[*].vmiKey',
                  equal: null,
                },
              ],
            },
            {
              and: [
                {
                  path: '[*].cimValue',
                  equal: 'true',
                },
                {
                  path: '[*].vmiKey',
                  notEqual: 'enable-oslogin',
                },
              ],
            },
            {
              and: [
                {
                  path: '[*].cimValue',
                  equal: 'true',
                },
                {
                  path: '[*].vmiKey',
                  equal: 'enable-oslogin',
                },
                {
                  path: '[*].vmiValue',
                  equal: 'true',
                },
              ],
            },
          ],
        },
      },
    ],
  },
}
