export default {
  id: 'azure-cis-1.3.1-7.6',  
  title: 'Azure CIS 7.6 Ensure that the endpoint protection for all Virtual Machines is installed (Manual)',
  
  description: 'Install endpoint protection for all virtual machines.',
  
  audit: `**From Azure Console**
  
  1. Go to Security Center - Recommendations
  2. Ensure that there are no recommendations for Endpoint Protection not installed on Azure VMs
  
  **Using Azure Command Line Interface 2.0**
  
      az vm show -g MyResourceGroup -n MyVm -d
  
  It should list below or any other endpoint extensions as one of the installed extensions.
  
      EndpointSecurity || TrendMicroDSA* || Antimalware || EndpointProtection || SCWPAgent || PortalProtectExtension* || FileSecurity*
  
  Alternatively, you can employ your own endpoint protection tool for your OS.`,
  
  rationale: 'Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software, with configurable alerts when known malicious or unwanted software attempts to install itself or run on Azure systems.',
  
  remediation: 'Follow Microsoft Azure documentation to install endpoint protection from the security center. Alternatively, you can employ your own endpoint protection tool for your OS.',
  
  references: [
      'https://docs.microsoft.com/en-us/azure/security-center/security-center-install-endpoint-protection',
      'https://docs.microsoft.com/en-us/azure/security/azure-security-antimalware',
      'https://docs.microsoft.com/en-us/cli/azure/vm/extension?view=azure-cli-latest#az_vm_extension_list',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-endpoint-security#es-1-use-endpoint-detection-and-response-edr',
  ],  
  severity: 'high'
}
