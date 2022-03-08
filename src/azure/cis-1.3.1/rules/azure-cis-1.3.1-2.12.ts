export default {
  id: 'azure-cis-1.3.1-2.12',  
  title: 'Azure CIS 2.12 Ensure any of the ASC Default policy setting is not set to "Disabled"',  
  
  description: 'None of the settings offered by ASC Default policy should be set to effect "Disabled".',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Security Center
  2. Click On the security policy to Open Policy Management Blade.
  3. Click Subscription View
  4. Click on Subscription Name to open Security Policy Blade for the Subscription.
  5. Expand All the available sections Compute And Apps, Data, Identity
  6. Ensure that any of the setting is not set to Disabled

  The 'View effective Policy' button can be used to see all effects of policies even if they have not been modified.
  
  **Using Azure Command Line Interface 2.0**  
  Ensure the output of the below command does not contains any setting which is set to Disabled or Empty
  
    az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1
    bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn?api-version=2018-05-01'
    
  **Note** policies that have not been modified will not be listed in this output`,
  
  rationale: `A security policy defines the desired configuration of your workloads and helps ensure
  compliance with company or regulatory security requirements. ASC Default policy is
  associated with every subscription by default. ASC default policy assignment is set of
  security recommendations based on best practices. Enabling recommendations in ASC
  default policy ensures that Azure security center provides ability to monitor all of the
  supported recommendations and allow automated action optionally for few of the
  supported recommendations.`,  
  
  remediation: `**From Azure Console**
  
  1. Navigate to Azure Policy
  2. On Policy "Overview" blade, Click on Policy ASC Default
  (Subscription:Subscription_ID)
  3. On "ASC Default" blade, Click on Edit Assignments
  4. In section PARAMETERS, configure the impacted setting to any other available value
  than Disabled or empty
  5. Click Save`,
  
  references: [
    'https://docs.microsoft.com/en-us/azure/security-center/security-center-policies',
    'https://docs.microsoft.com/en-us/azure/security-center/security-center-enable-transparent-data-encryption',
    'https://msdn.microsoft.com/en-us/library/mt704062.aspx',
    'https://msdn.microsoft.com/en-us/library/mt704063.aspx',
    'https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/get',
    'https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/create',
    'https://docs.microsoft.com/en-in/azure/security-center/tutorial-security-policy',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-incident-response#ir-2-preparation--setup-incident-notification',
  ],  
  severity: 'medium',
}
