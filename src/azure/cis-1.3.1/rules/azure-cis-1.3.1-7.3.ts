export default {
  id: 'azure-cis-1.3.1-7.3',  
  title: 'Azure CIS 7.3 Ensure that \'Unattached disks\' are encrypted with CMK',
  
  description: 'Ensure that unattached disks in a subscription are encrypted with a Customer Managed Key (CMK).',
  
  audit: `**From Azure Console**
  
  1. Go to Disks
  2. Click on Add Filter
  3. In the filter field select Disk state
  4. In the Value field select Unattached
  5. Click Apply
  6. for each disk listed ensure that Encryption type in the encryption blade is 'Encryption at-rest with a customer-managed key'
  
  **From Azure Command Line Interface 2.0**  
  Ensure command below does not return any output.
  
      az disk list --query '[? diskstate == 'Unattached'].{encryptionSettings: encryptionSettings, name: name}' -o json
  
  Sample Output:
  
      [ 
          { 
              "encryptionSettings": null,
              "name": "<Disk1>"
          },
          {
              "encryptionSettings": null,
              "name": "<Disk2>"
          }
      ]`,
  
  rationale: 'Managed disks are encrypted by default with Platform-managed keys. Using Customer-managed keys may provide an additional level of security or meet an organization\'s regulatory requirements. Encrypting managed disks ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads. Even if the disk is not attached to any of the VMs, there is always a risk where a compromised user account with administrative access to VM service can mount/attach these data disks which may lead to sensitive information disclosure and tampering.',
  
  remediation: `**Remediation:**
  
  If data stored in the disk is no longer useful, refer to Azure documentation to delete unattached data disks at:
  
      -https://docs.microsoft.com/en-us/rest/api/compute/disks/delete -https://docs.microsoft.com/en-us/cli/azure/disk?view=azure-cli-latest#az-disk-delete
  
  If data stored in the disk is important, To encrypt the disk refer azure documentation at:
  
      -https://docs.microsoft.com/en-us/azure/virtual-machines/disks-enable-customer-managed-keys-portal
      -https://docs.microsoft.com/en-us/rest/api/compute/disks/update#encryptionsettings`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/security/fundamentals/azure-disk-encryption-vms-vmss',
      'https://docs.microsoft.com/en-us/azure/security-center/security-center-disk-encryption?toc=%2fazure%2fsecurity%2ftoc.json',
      'https://docs.microsoft.com/en-us/rest/api/compute/disks/delete',
      'https://docs.microsoft.com/en-us/cli/azure/disk?view=azure-cli-latest#az-disk-delete',
      'https://docs.microsoft.com/en-us/rest/api/compute/disks/update#encryptionsettings',
      'https://docs.microsoft.com/en-us/cli/azure/disk?view=azure-cli-latest#az-disk-update',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-5-encrypt-sensitive-data-at-rest',
  ],  
  gql: `{
    queryazureDisk { 
      id
      __typename
      diskState
      encryptionSettings
    }
  }`,
  resource: 'queryazureDisk[*]',
  severity: 'medium',
  conditions: {
    or: [
      {
        path: '@.diskState',
        notEqual: 'Unattached',
      },
      {
        path: '@.encryptionSettings',
        match: /CustomerKey/,
      },
    ],
  },
}
