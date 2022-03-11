export default {
  id: 'azure-cis-1.3.1-7.5',  
  title: 'Azure CIS 7.5 Ensure that the latest OS Patches for all Virtual Machines are applied (Manual)',
    
  description: 'Ensure that the latest OS patches for all virtual machines are applied.',
    
  audit: `**From Azure Console**
    
  1. Go to Security Center - Recommendations
  2. Ensure that there are no recommendations for Apply system updates
    
  Alternatively, you can employ your own patch assessment and management tool to periodically assess, report and install the required security patches for your OS.  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
    
  rationale: `Windows and Linux virtual machines should be kept updated to:
    
  - Address a specific bug or flaw
  - Improve an OS or application’s general stability
  - Fix a security vulnerability
  
  The Azure Security Center retrieves a list of available security and critical updates from Windows Update or Windows Server Update Services (WSUS), depending on which service is configured on a Windows VM. The security center also checks for the latest updates in Linux systems. If a VM is missing a system update, the security center will recommend system updates be applied.`,
    
  remediation: 'Follow Microsoft Azure documentation to apply security patches from the security center. Alternatively, you can employ your own patch assessment and management tool to periodically assess, report and install the required security patches for your OS.',
    
  references: [
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-posture-vulnerability-management#pv-7-rapidly-and-automatically-remediate-software-vulnerabilities'
  ],  
  severity: 'high'
}
