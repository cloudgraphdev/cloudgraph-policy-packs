export default {
  id: 'azure-cis-1.3.1-2.1',  
  title: 'Azure CIS 2.1 Ensure that Azure Defender is set to On for Servers',  
  
  description: 'Turning on Azure Defender enables threat detection for Server, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center.',
  
  audit: `**From Azure Console**
  
  1. Go to Security Center
  2. Select Pricing & settings blade
  3. Click on the subscription name
  4. Select the Azure Defender plans blade
  5. Review the chosen pricing tier. For the Servers resource type Plan should be set to On.
  
  **Using Azure Command Line Interface 2.0**  
  Ensure the output of the below command is Standard
  
      az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/pricings?api-version=2018-06-01' | jq '.|.value[] | select(.name=="VirtualMachines")'|jq '.properties.pricingTier'
  
  **Using PowerShell**
  
      Connect-AzAccount
      Get-AzSecurityPricing | Where-Object {$_.Name -eq 'VirtualMachines'} | Select-Object Name, PricingTier
  
  Ensure output of command is VirtualMachines Standard`,
  
  rationale: 'Enabling Azure Defender for Servers allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).',  
  
  remediation: `**From Azure Console**
  
  1. Go to Security Center
  2. Select Pricing & settings blade
  3. Click on the subscription name
  4. Select the Azure Defender plans blade
  5. On the line in the table for Servers Select On under Plan.
  6. Select Save
  
  **Using Azure Command Line Interface 2.0**  
  Use the below command to enable Azure Defender for Servers
  
      az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c 'curl -X PUT -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/pricings/VirtualMachines?api-version=2018-06-01 -d@"input.json"'
  
  Where input.json contains the Request body json data as mentioned below.
  
      {
          "id": "/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/pricings/VirtualMachines",
          "name": "VirtualMachines",
          "type": "Microsoft.Security/pricings",
          "properties": { 
              "pricingTier": "Standard" 
          }
      }`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities',
      'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/list',
      'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/update',
      'https://docs.microsoft.com/en-us/powershell/module/az.security/get-azsecuritypricing',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-endpoint-security#es-1-use-endpoint-detection-and-response-edr',
  ],  
  gql: `{
    queryazureSecurityPricing {
      id
      __typename
      name
      pricingTier
    }
  }`,
  resource: 'queryazureSecurityPricing[*]',
  severity: 'high',
  conditions: {
    or: [
      {
        path: '@.name',
        notEqual: 'VirtualMachines',
      },
      {
        path: '@.pricingTier',
        equal: 'Standard',
      },
    ],
  },
}
