export default {
  id: 'azure-cis-1.3.1-2.11',  
  title: `Azure CIS 2.11 Ensure that 'Automatic provisioning of monitoring agent' is set to 'On'`,  
  
  description: 'Enable automatic provisioning of the monitoring agent to collect security data.',
  
  audit: `**From Azure Console**
  
  1. Go to Security Center
  2. Click on Pricing & Settings
  3. Click on a subscription
  4. Click on Data Collection
  5. Ensure that Automatic provisioning is set to On

  Repeat the above for any additional subscriptions.
  
  **Using Azure Command Line Interface 2.0**  
  Ensure the output of the below command is On
  
    az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1
    bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/autoProvisioningSettings?api-version=2017-08-01-preview' | jq '.|.value[] | select(.name=="default")'|jq '.properties.autoProvision'
  
  **Using PowerShell**

    Connect-AzAccount
    Get-AzSecurityAutoProvisioningSetting

  Ensure output for Id Name AutoProvision' is /subscriptions//providers/Microsoft.Security/autoProvisioningSettings/default default On`,

  rationale: `When Automatic provisioning of monitoring agent is turned on, Azure Security Center
  provisions the Microsoft Monitoring Agent on all existing supported Azure virtual
  machines and any new ones that are created. The Microsoft Monitoring Agent scans for
  various security-related configurations and events such as system updates, OS
  vulnerabilities, endpoint protection, and provides alerts.`,  
  
  remediation: `**From Azure Console**
  
  1. Go to Security Center
  2. Click on Pricing & Settings
  3. Click on a subscription
  4. Click on Data Collection
  5. Set Automatic provisioning to On
  6. Click save

  Repeat the above for any additional subscriptions.
  
  Using Azure Command Line Interface 2.0 Use the below command to set Automatic provisioning of monitoring agent to On.
  
    az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1
    bash -c 'curl -X PUT -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/autoProvisioningSettings/default?api-version=2017-08-01-preview -d@"input.json"'
  
  Where input.json contains the Request body json data as mentioned below.
  
    {
      "id": "/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/autoProvisioningSettings/default",
      "name": "default",
      "type": "Microsoft.Security/autoProvisioningSettings",
      "properties": {
        "autoProvision": "On"
      }
    }
  
  **Default Value**:
  By default, Automatic provisioning of monitoring agent is set to On.`,
  
  references: [
    'https://docs.microsoft.com/en-us/azure/security-center/security-center-data-security',
    'https://docs.microsoft.com/en-us/azure/security-center/security-center-enable-data-collection',
    'https://msdn.microsoft.com/en-us/library/mt704062.aspx',
    'https://msdn.microsoft.com/en-us/library/mt704063.aspx',
    'https://docs.microsoft.com/en-us/rest/api/securitycenter/autoprovisioningsettings/list',
    'https://docs.microsoft.com/en-us/rest/api/securitycenter/autoprovisioningsettings/create',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-incident-response#ir-2-preparation--setup-incident-notification',
  ],  
  gql: `{
    queryazureAutoProvisioningSetting {
      id
      __typename
      name
      autoProvision
    }
  }`,
  resource: 'queryazureAutoProvisioningSetting[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.name',
        equal: 'default',
      },
      {
        path: '@.autoProvision',
        equal: 'On',
      },
    ],
  },
}
