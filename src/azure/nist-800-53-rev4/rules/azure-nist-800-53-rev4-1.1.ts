export default {
  id: 'azure-nist-800-53-rev4-1.1',  
  title: 'Azure NIST 1.1 Virtual Machines unattached disks should be encrypted',
  
  description: 'Encrypting the IaaS VM’s disks ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**Azure Portal**
  
  To encrypt unattached Linux VM data disks:
  
  - Follow the [Azure documentation](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/attach-disk-portal) to attach the disk to the VM
  - Follow the [Azure documentation](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption-portal-quickstart#encrypt-the-virtual-machine) to encrypt the VM, but select “Data disks” instead of “OS and data disks”
  
  To encrypt unattached Windows VM data disks:
  
  - Follow the [Azure documentation](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/attach-managed-disk-portal) to attach the disk to the VM
  - Follow the [Azure documentation](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-portal-quickstart#encrypt-the-virtual-machine) to encrypt the VM. Data disks can only be encrypted if the OS disk is encrypted.
    
  **Azure CLI**
  
  To encrypt unattached Linux VM data disks:
    
  [Attach the disk to the VM](https://docs.microsoft.com/en-us/cli/azure/vm/disk?view=azure-cli-latest#az-vm-disk-attach):
    
      az vm disk attach --disk $diskId --new --resource-group MyResourceGroup --size-gb 128 --sku Standard_LRS --vm-name MyVm
    
  [Enable encryption on the VM data disk](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption-linux#enable-encryption-on-a-newly-added-data-disk):
    
      az vm encryption enable --resource-group "MyVirtualMachineResourceGroup" --name "MySecureVM" --disk-encryption-keyvault "MySecureVault" --volume-type "Data"
    
  To encrypt unattached Windows VM data disks:
    
  [Attach the disk to the VM](https://docs.microsoft.com/en-us/cli/azure/vm/disk?view=azure-cli-latest#az-vm-disk-attach):
    
      az vm disk attach --disk $diskId --new --resource-group MyResourceGroup --size-gb 128 --sku Standard_LRS --vm-name MyVm
    
  Data disks can only be encrypted if the OS disk is encrypted. [Enable encryption on the VM](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-windows#enable-encryption-on-a-newly-added-disk-with-azure-cli):
    
      az vm encryption enable --resource-group "MyVirtualMachineResourceGroup" --name "MySecureVM" --disk-encryption-keyvault "MySecureVault" --volume-type "All"`,
    
  references: [
    'https://docs.microsoft.com/en-us/azure/virtual-machines/linux/attach-disk-portal',
    'https://docs.microsoft.com/en-us/cli/azure/vm/disk?view=azure-cli-latest#az-vm-disk-attach',
    'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/attach-managed-disk-portal',
    'https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption-portal-quickstart#encrypt-the-virtual-machine',
    'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-windows#enable-encryption-on-a-newly-added-disk-with-azure-cli',
    'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-portal-quickstart#encrypt-the-virtual-machine',
    'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-windows#enable-encryption-on-a-newly-added-disk-with-azure-cli',
  ],
  gql: `{
    queryazureDisk {
      id
      __typename
      diskState
      azureDiskEncryptionEnabled
    }
  }`,
  resource: 'queryazureDisk[*]',
  severity: 'high',
  conditions: {
    or: [
      {
        path: '@.diskState',
        notEqual: 'Unattached',
      },
      {
        path: '@.azureDiskEncryptionEnabled',
        equal: true,
      },
    ],
  },
}
