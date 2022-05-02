export default {
  id: 'azure-cis-1.3.1-7.2',  
  title: 'Azure CIS 7.2 Ensure that \'OS and Data\' disks are encrypted with CMK',
  
  description: 'Ensure that OS disks (boot volumes) and data disks (non-boot volumes) are encrypted with CMK.',
  
  audit: `**From Azure Console**
 
  1. Go to Virtual machines
  2. For each virtual machine, go to Settings
  3. Click on Disks
  4. Ensure that the OS disk and Data disks have encryption set to CMK.
  
  **Using PowerShell**
  
      $ResourceGroupName="yourResourceGroupName"
      $DiskName="yourDiskName"
  
      $disk=Get-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $DiskName $disk.Encryption.Type`,
    
  rationale: 'Encrypting the IaaS VM\'s OS disk (boot volume), Data disks (non-boot volume) ensures that the entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads. CMK is superior encryption although requires additional planning.',
  
  remediation: `**From Azure Console**  
  **Note:** Disks must be detached from VMs to have encryption changed.
    
  1. Go to Virtual machines
  2. For each virtual machine, go to Settings
  3. Click on Disks
  4. Click the X to detach the disk from the VM
  5. Now search for Disks and locate the unattached disk
  6. Click the disk then select Encryption
  7. Change your encryption type, then select your encryption set
  8. Click Save
  9. Go back to the VM and re-attach the disk
    
  **Using PowerShell**
    
      $KVRGname = 'MyKeyVaultResourceGroup';
      $VMRGName = 'MyVirtualMachineResourceGroup';
      $vmName = 'MySecureVM';
      $KeyVaultName = 'MySecureVault';
      $KeyVault = Get-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $KVRGname;
      $diskEncryptionKeyVaultUrl = $KeyVault.VaultUri;
      $KeyVaultResourceId = $KeyVault.ResourceId;
    
      Set-AzVMDiskEncryptionExtension -ResourceGroupName $VMRGname -VMName $vmName -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $KeyVaultResourceId;
    
  **NOTE:** During encryption it is likely that a reboot will be required, it may take up to 15 minutes to complete the process.  
  **NOTE 2:** This may differ for Linux Machines as you may need to set the -skipVmBackup parameter`,
    
  references: [
  'https://docs.microsoft.com/azure/security/fundamentals/azure-disk-encryption-vms-vmss',
  'https://docs.microsoft.com/en-us/azure/security-center/security-center-disk-encryption?toc=%2fazure%2fsecurity%2ftoc.json',
  'https://docs.microsoft.com/azure/security/fundamentals/data-encryption-best-practices#protect-data-at-resthttps://docs.microsoft.com/azure/virtual-machines/windows/disk-encryption-portal-quickstart',
  'https://docs.microsoft.com/en-us/rest/api/compute/disks/delete',
  'https://docs.microsoft.com/en-us/rest/api/compute/disks/update#encryptionsettings',
  'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-5-encrypt-sensitive-data-at-rest',
  'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disks-enable-customer-managed-keys-powershell',
  ],  
  gql: `{
    queryazureDisk { 
      id
      __typename
      encryptionSettings
    }
  }`,
  resource: 'queryazureDisk[*]',
  severity: 'medium',
  conditions: {
    path: '@.encryptionSettings',
    match: /CustomerKey/,
  },
}
