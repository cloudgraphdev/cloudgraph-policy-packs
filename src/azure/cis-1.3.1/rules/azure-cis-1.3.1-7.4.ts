export default {
  id: 'azure-cis-1.3.1-7.4',  
  title: 'Azure CIS 7.4 Ensure that only approved extensions are installed (Manual)',
  
  description: 'Only install organization-approved extensions on VMs.',
  
  audit: `**From Azure Console**
  
  1. Go to Virtual machines
  2. For each virtual machine, go to Settings
  3. Click on Extensions
  4. Ensure that the listed extensions are approved for use.
  
  **From Azure Command Line Interface 2.0**  
  Use the below command to list the extensions attached to a VM, and ensure the listed extensions are approved for use.
  
      az vm extension list --vm-name <vmName> --resource-group <sourceGroupName> --query [*].name`,
  
  rationale: 'Azure virtual machine extensions are small applications that provide post-deployment configuration and automation tasks on Azure virtual machines. These extensions run with administrative privileges and could potentially access anything on a virtual machine. The Azure Portal and community provide several such extensions. Each organization should carefully evaluate these extensions and ensure that only those that are approved for use are actually implemented.',
  
  remediation: `**From Azure Console**
  
  1. Go to Virtual machines
  2. For each virtual machine, go to Settings
  3. Click on Extensions
  4. If there are unapproved extensions, uninstall them.
  
  **From Azure Command Line Interface 2.0**  
  From the audit command identify the unapproved extensions, and use the below CLI command to remove an unapproved extension attached to VM.
  
      az vm extension delete --resource-group <resourceGroupName> --vm-name <vmName> --name <extensionName>`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/extensions-features',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-endpoint-security',
  ],  
  severity: 'high'
}
