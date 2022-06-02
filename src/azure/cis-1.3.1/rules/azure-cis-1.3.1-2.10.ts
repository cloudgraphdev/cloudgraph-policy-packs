export default {
  id: 'azure-cis-1.3.1-2.10',  
  title: 'Azure CIS 2.10 Ensure that Microsoft Cloud App Security (MCAS) integration with Security Center is selected',  
  
  description: 'This setting enables Microsoft Cloud App Security (MCAS) integration with Security Center.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Security Center
  2. Select Pricing & settings blade
  3. Click on the subscription name
  4. Select the Threat Detection blade
  5. Ensure setting Allow Microsoft Cloud App Security to access my data is
  selected.
  
  **Using Azure Command Line Interface 2.0**  
  Ensure the output of the below command is True
  
    az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1
    bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/settings?api-version=2019-01-01' | jq '.|.value[] | select(.name=="MCAS")'| jq '.properties.enabled'`,
  
  rationale: `Security Center offers an additional layer of protection by using Azure Resource Manager
  events, which is considered to be the control plane for Azure. By analyzing the Azure
  Resource Manager records, Security Center detects unusual or potentially harmful
  operations in the Azure subscription environment. Several of the preceding analytics are
  powered by Microsoft Cloud App Security. To benefit from these analytics, subscription
  must have a Cloud App Security license.
  MCAS works only with Standard Tier subscriptions.`,  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Security Center
  2. Select Security policy blade
  3. Click On Edit Settings to alter the the security policy for a subscription
  4. Select the Threat Detection blade
  5. Check/Enable option Allow Microsoft Cloud App Security to access my data
  6. Select Save
  
  Using Azure Command Line Interface 2.0 Use the below command to enable Standard pricing tier for Storage Accounts
  
    az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1
    bash -c 'curl -X PUT -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/settings/MCAS?api-version=2019-01-01 -d@"input.json"'
  
  Where input.json contains the Request body json data as mentioned below.
  
    {
      "id": "/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/settings/MCAS",
      "kind": "DataExportSetting",
      "type": "Microsoft.Security/settings",
      "properties": {
        "enabled": true
      }
    }`,
  
  references: [
    'https://docs.microsoft.com/en-in/azure/security-center/security-center-alerts-service-layer#azure-management-layer-azure-resource-manager-preview',
    'https://docs.microsoft.com/en-us/rest/api/securitycenter/settings/list',
    'https://docs.microsoft.com/en-us/rest/api/securitycenter/settings/update',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-identity-management#im-8-secure-user-access-to-legacy-applications',
  ],  
  gql: `{
    queryazureSecuritySetting {
      id
      __typename
      name
      enabled
    }
  }`,
  resource: 'queryazureSecuritySetting[*]',
  severity: 'high',
  conditions: {
    or: [
      {
        path: '@.name',
        notEqual: 'MCAS',
      },
      {
        path: '@.enabled',
        equal: true,
      },
    ],
  },
}
