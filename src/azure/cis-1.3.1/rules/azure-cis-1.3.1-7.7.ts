export default {
  id: 'azure-cis-1.3.1-7.7',  
  title: 'Azure CIS 7.7 Ensure that VHD\'s are encrypted (Manual)',
    
  description: 'VHD (Virtual Hard Disks) are stored in BLOB storage and are the old style disks that were attached to Virtual Machines, and the BLOB VHD was then leased to the VM. By Default storage accounts are not encrypted, and Azure Defender(Security Centre) would then recommend that the OS disks should be encrypted. Storage accounts can be encrypted as a whole using PMK or CMK and this should be turned on for storage accounts containing VHD\'s.',
    
  audit: `**Using Azure Command Line Interface:**  
  Disk Encryption for a VM can be checked in Azure CLI using the following command.
    
      az vm encryption show --name MyVM -g MyResourceGroup`,
    
  rationale: 'With the changes that have been made that recommend using managed disks that are encrypted by default, we need to also have a recommendation that "legacy" disk that may for a number of reasons need to be left as VHD\'s should also be encrypted to protect the data content.',
    
  remediation: `**From Azure Portal**
  
  1. Navigate to the storage account that you wish to encrypt
  2. Select the encryption option
  3. Select the key type that you wish to use
  
  If you wish to use an azure managed key (the default), you can save at this point and encryption will be applied to the account.  
  If you select customer managed key it will ask for the location of the key (The default is an Azure Keyvault) and the key name.  
  Once these are captured, save the configuration and the account will be encrypted using the provided key.
    
  **Using Azure Command Line Interface:**  
  **Create the Keyvault**
    
      az keyvault create --name "myKV" --resource-group "myResourceGroup" --location eastus --enabled-for-disk-encryption
    
  **Encrypt the disk and store the key in keyvault**
    
      az vm encryption enable -g MyResourceGroup --name MyVM --disk-encryption-keyvault myKV
    
  **Using Azure Powershell**  
  This process uses a keyvault to store the keys
  **Create the Keyvault**
    
      New-AzKeyvault -name MyKV -ResourceGroupName myResourceGroup -Location EastUS -EnabledForDiskEncryption
    
  **Encrypt the disk and store the key in keyvault**
    
      $KeyVault = Get-AzKeyVault -VaultName MyKV -ResourceGroupName MyResourceGroup
        
      Set-AzVMDiskEncryptionExtension -ResourceGroupName MyResourceGroup -VMName MyVM -DiskEncryptionKeyVaultUrl $KeyVault.VaultUri -DiskEncryptionKeyVaultId $KeyVault.ResourceId`,
    
  references: [  
      'CLI: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-cli-quickstart',  
      'Powershell: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-powershell-quickstart',  
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-5-encrypt-sensitive-data-at-rest',
  ],  
  severity: 'medium'
}
