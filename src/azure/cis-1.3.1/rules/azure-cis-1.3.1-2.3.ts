export default {
  id: 'azure-cis-1.3.1-2.3',  
  title: 'Azure CIS 2.3 Ensure that Azure Defender is set to On for Azure SQL database servers',  
  
  description: 'Turning on Azure Defender enables threat detection for Azure SQL database servers, providing threat intelligence, anomaly detection, and behavior analytics in the Azure Security Center.',
  
  audit: `**From Azure Console**
  
  1. Go to Security Center
  2. Select Pricing & settings blade
  3. Click on the subscription name
  4. Select the Azure Defender plans blade
  5. Review the chosen pricing tier. For the Azure SQL database servers resource type Plan should be set to On.
  
  **Using Azure Command Line Interface 2.0**  
  Ensure the output of the below command is Standard
  
      az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/pricings?api-version=2018-06-01' | jq '.|.value[] | select(.name=="SqlServers")'|jq '.properties.pricingTier'
  
  **Using PowerShell**
  
      Connect-AzAccount
      Get-AzSecurityPricing | Where-Object {$_.Name -eq 'SqlServers'} | Select-Object Name, PricingTier
  
  Ensure output for Name PricingTier is SqlServers Standard`,
  
  rationale: 'Enabling Azure Defender for Azure SQL database servers allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).',  
  
  remediation: `**From Azure Console**
  
  1. Go to Security Center
  2. Select Pricing & settings blade
  3. Click on the subscription name
  4. Select the Azure Defender plans blade
  5. On the line in the table for Azure SQL database servers Select On under Plan.
  6. Select Save
  
  **Using Azure Command Line Interface 2.0**  
  Use the below command to enable Standard pricing tier for Azure SQL database servers
  
      az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c 'curl -X PUT -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/pricings/SqlServers?api-version=2018-06-01 -d@"input.json"'
  
  Where input.json contains the Request body json data as mentioned below.
  
      {
          "id": "/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/pricings/SqlServers",
          "name": "SqlServers",
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
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-3-monitor-for-unauthorized-transfer-of-sensitive-data',
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
        notEqual: 'SqlServers',
      },
      {
        path: '@.pricingTier',
        equal: 'Standard',
      },
    ],
  },
}
