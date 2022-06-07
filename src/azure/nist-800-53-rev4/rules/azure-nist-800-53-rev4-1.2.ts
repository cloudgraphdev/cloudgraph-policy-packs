export default {
  id: 'azure-nist-800-53-rev4-1.2',  
  title: 'Azure NIST 1.2 Virtual Machines data disks (non-boot volumes) should be encrypted',
  
  description: 'Encrypting the IaaS VM’s Data disks ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**Azure Portal**
  
  To encrypt Linux VM data disks:
  
  - Follow the [Azure documentation](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption-portal-quickstart#encrypt-the-virtual-machine), but select “Data disks” instead of “OS and data disks.”
  
  To encrypt Windows VM data disks:
  
  - Follow the [Azure documentation](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-portal-quickstart#encrypt-the-virtual-machine). Data disks can only be encrypted if the OS disk is encrypted.
  
  **Azure CLI**
  
  To encrypt Linux VM data disks:
  
  [Enable encryption on the VM data disk](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption-linux#enable-encryption-on-a-newly-added-data-disk):
  
      az vm encryption enable --resource-group "MyVirtualMachineResourceGroup" --name "MySecureVM" --disk-encryption-keyvault "MySecureVault" --volume-type "Data"
  
  To encrypt Windows VM data disks:
  
  Data disks can only be encrypted if the OS disk is encrypted. [Enable encryption on the VM](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-windows#enable-encryption-on-a-newly-added-disk-with-azure-cli):
  
      az vm encryption enable --resource-group "MyVirtualMachineResourceGroup" --name "MySecureVM" --disk-encryption-keyvault "MySecureVault" --volume-type "All"`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption-portal-quickstart#encrypt-the-virtual-machine',
      'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-windows#enable-encryption-on-a-newly-added-disk-with-azure-cli',
      'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-portal-quickstart#encrypt-the-virtual-machine',
      'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-windows#enable-encryption-on-a-newly-added-disk-with-azure-cli',
  ],
  gql: `{
    queryazureVirtualMachine {
      id
      __typename
      disks {
        osType
        azureDiskEncryptionEnabled
      }
    }
  }`,
  resource: 'queryazureVirtualMachine[*]',
  severity: 'high',
  conditions: {
    not: {
      path: '@.disks',
      array_any: {
        and: [
          {
            path: '[*].osType',
            equal: null,
          },
          {
            path: '[*].azureDiskEncryptionEnabled',
            equal: false,
          },
        ],
      },
    },
  }, 
}
