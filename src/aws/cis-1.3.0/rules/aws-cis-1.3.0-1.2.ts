export default {
  id: 'aws-cis-1.3.0-1.2',  
  title: 'AWS CIS 1.2 Ensure security contact information is registered',
  
  description: 'AWS provides customers with the option of specifying the contact information for account\'s security team. It is recommended that this information be provided.',
  
  audit: `Perform the following to determine if security contact information is present:
  
  **From Console:**
  
  1. Click on your account name at the top right corner of the console
  2. From the drop-down menu Click My Account
  3. Scroll down to the Alternate Contacts section
  4. Ensure contact information is specified in the Security section`,
  
  rationale: 'Specifying security-specific contact information will help ensure that security advisories sent by AWS reach the team in your organization that is best equipped to respond to them.',
  
  remediation: `Perform the following to establish security contact information:
  
  **From Console:**
  
  1. Click on your account name at the top right corner of the console.
  2. From the drop-down menu Click My Account
  3. Scroll down to the Alternate Contacts section
  4. Enter contact information in the Security section
  
  **Note**: Consider specifying an internal email distribution list to ensure emails are regularly monitored by more than one individual.`,
  
  references: ['CCE-79200-2'],
  
  severity: 'medium',
}
