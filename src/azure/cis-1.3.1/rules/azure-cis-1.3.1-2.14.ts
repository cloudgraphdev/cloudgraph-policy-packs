export default {
  id: 'azure-cis-1.3.1-2.14',  
  title: 'Azure CIS 2.14 Ensure that "Notify about alerts with the following severity" is set to "High"',  
  
  description: 'Enables emailing security alerts to the subscription owner or other designated security contact.',
  
  audit: `**From Azure Console**
  
  1. Go to Security Center
  2. Click on Pricing & settings
  3. Click on the appropriate Management Group, Subscription, or Workspace
  4. Click on Email notifications
  5. Ensure that the Notify about alerts with the following severity (or higher) setting is checked and set to High
  
  **Using Azure Command Line Interface 2.0**  
  Ensure the output of below command is set to true.
  
    az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1
    bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/securityContacts?api-version=2017-08-01-preview' | jq '.|.value[] | select(.name=="default1")'| jq '.properties.alertNotifications'`,
  
  rationale: `Enabling security alert emails ensures that security alert emails are received from
  Microsoft. This ensures that the right people are aware of any potential security issues and
  are able to mitigate the risk.`,  
  
  remediation: `**From Azure Console**
  
  1. Go to Security Center
  2. Click on Pricing & settings
  3. Click on the appropriate Management Group, Subscription, or Workspace
  4. Click on Email notifications
  5. Under 'Notification types', check the check box next to Notify about alerts with
  the following severity (or higher): and select High from the drop down menu
  6. Click Save

  **Using Azure Command Line Interface 2.0**  
  Use the below command to set Send email notification for high severity alerts to On.

    az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1
    bash -c 'curl -X PUT -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/securityContacts/default1?api-version=2017-08-01-preview -d@"input.json"'
  
  Where input.json contains the Request body json data as mentioned below. And replace validEmailAddress with email ids csv for multiple.

    {
      "id": "/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/securityContacts/default1",
      "name": "default1",
      "type": "Microsoft.Security/securityContacts",
      "properties": {
        "email": "<validEmailAddress>",
        "alertNotifications": "On",
        "alertsToAdmins": "On"
      }
    }

  **Default Value**:
  By default, Send email notification for high severity alerts is not set.`,
  
  references: [
    'https://docs.microsoft.com/en-us/azure/security-center/security-center-provide-security-contact-details',
    'https://docs.microsoft.com/en-us/rest/api/securitycenter/securitycontacts/list',
    'https://docs.microsoft.com/en-us/rest/api/securitycenter/securitycontacts/update',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-incident-response#ir-2-preparation--setup-incident-notification',
  ],  
  gql: `{
    queryazureSecurityContact {
      id
      __typename
      name
      alertNotifications
    }
  }`,
  resource: 'queryazureSecurityContact[*]',
  severity: 'high',
  conditions: {
    or: [
      {
        path: '@.name',
        notEqual: 'default1',
      },
      {
        path: '@.alertNotifications',
        equal: 'On',
      },
    ],
  },
}
