export default {
  id: 'azure-cis-1.3.1-7.1',  
  title: 'Azure CIS 7.1 Ensure Virtual Machines are utilizing Managed Disks (Manual)',
    
  description: `Migrate BLOB based VHD's to Managed Disks on Virtual Machines to exploit the default features of this configuration. The features include
    
  1. Default Disk Encryption
  2. Resilience as Microsoft will managed the disk storage and move around if underlying hardware goes faulty
  3. Reduction of costs over storage accounts`,
    
  audit: `**From Azure Console**
    
  1. Using the search feature, go to Virtual Machines
  2. Select Edit columns
  3. Add Uses managed disks to the selected columns
  4. Select Apply
  5. Ensure virtual machine listed are using a managed disk
    
  **Using Powershell**
   
      Get-AzVM | ForEach-Object {"Name: " + $_.Name;"ManagedDisk Id: " + $_.StorageProfile.OsDisk.ManagedDisk.Id;""}
   
  **Example output:**
    
      Name: vm1
      ManagedDisk Id: /disk1/id
  
      Name: vm2
      ManagedDisk Id: /disk2/id
  
  If the 'ManagedDisk Id' field is empty the os disk for that vm is not managed.`,
  
  rationale: `Managed disks are by default encrypted on the underlying hardware so no additional encryption is required for basic protection, it is available if additional encryption is required. Managed disks are by design more resilient that storage accounts.
  
  For ARM deployed Virtual Machines, Azure Adviser will at some point recommend moving VHD's to managed disks both from a security and cost management perspective.`,
  
  remediation: `**From Azure Console**
  
  1. Using the search feature, go to Virtual Machines
  2. Select the virtual machine you would like to convert
  3. Select Disks in the menu for the VM
  4. At the top select Migrate to managed disks
  5. You may follow the prompts to convert the disk and finish by selecting 'Migrate' to start the process
  
  **NOTE** VMs will be stopped and restarted after migration is complete.
  
  **Using Powershell**
    
      Stop-AzVM -ResourceGroupName $rgName -Name $vmName -Force ConvertTo-AzVMManagedDisk -ResourceGroupName $rgName -VMName $vmName Start-AzVM -ResourceGroupName $rgName -Name $vmName`,
    
  references: [
      'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/convert-unmanaged-to-managed-disks',  
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-1-define-asset-management-and-data-protection-strategy',  
  ],  
  severity: 'high'
}
