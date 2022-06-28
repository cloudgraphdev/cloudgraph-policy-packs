export default {
  id: 'azure-cis-1.3.1-2.9',  
  title: 'Azure CIS 2.9 Ensure that Windows Defender ATP (WDATP) integration with Security Center is selected',  
  
  description: 'This setting enables Windows Defender ATP (WDATP) integration with Security Center.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Security Center
  2. Select Pricing & settings blade
  3. Click on the subscription name
  4. Select the Threat Detection blade
  5. Ensure setting Allow Windows Defender ATP to access my data is selected.
  
  **Using Azure Command Line Interface 2.0**  
  Ensure the output of the below command is True
  
    az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1
    bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/settings?api-version=2019-01-01' | jq '.|.value[] | select(.name=="WDATP")'|jq '.properties.enabled'`,
  
  rationale: `WDATP integration brings comprehensive Endpoint Detection and Response (EDR)
  capabilities within security center. This integration helps to spot abnormalities, detect and
  respond to advanced attacks on Windows server endpoints monitored by Azure Security
  Center. Windows Defender ATP in Security Center supports detection on Windows Server
  2016, 2012 R2, and 2008 R2 SP1 operating systems in a Standard service subscription.
  WDATP works only with Standard Tier subscriptions.`,  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Security Center
  2. Select Security policy blade
  3. Click On Edit Settings to alter the the security policy for a subscription
  4. Select the Threat Detection blade
  5. Check/Enable option Allow Windows Defender ATP to access my data
  6. Select Save
  
  Using Azure Command Line Interface 2.0 Use the below command to enable Standard pricing tier for Storage Accounts
  
    az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1
    bash -c 'curl -X PUT -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/settings/WDATP?api-version=2019-01-01 -d@"input.json"'
  
  Where input.json contains the Request body json data as mentioned below.
  
    {
      "id": "/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/settings/WDATP",
      "kind": "DataExportSetting",
      "type": "Microsoft.Security/settings",
      "properties": {
        "enabled": true
      }
    }`,
  
  references: [
    'https://docs.microsoft.com/en-in/azure/security-center/security-center-wdatp',
    'https://docs.microsoft.com/en-us/rest/api/securitycenter/settings/list',
    'https://docs.microsoft.com/en-us/rest/api/securitycenter/settings/update',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-endpoint-security#es-1-use-endpoint-detection-and-response-edr',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-endpoint-security#es-2-use-centrally-managed-modern-anti-malware-software',
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
        notEqual: 'WDATP',
      },
      {
        path: '@.enabled',
        equal: true,
      },
    ],
  },
}
