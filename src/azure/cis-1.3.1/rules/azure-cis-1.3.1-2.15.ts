export default {
  id: 'azure-cis-1.3.1-2.15',  
  title: 'Azure CIS 2.15 Ensure that "All users with the following roles" is set to "Owner"',
  
  description: 'Enable security alert emails to subscription owners.',
  
  audit: `**From Azure Console**
  
  1. Go to Security Center
  2. Click on Pricing & settings
  3. Click on the appropriate Management Group, Subscription, or Workspace
  4. Click on Email notifications
  5. Ensure that All users with the following roles is set to Owner
  
  **Using Azure Command Line Interface 2.0**  
  Ensure the output of below command is set to true.
  
          az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/securityContacts?api-version=2017-08-01-preview' | jq '.|.value[] | select(.name=="default1")'|jq '.properties.alertsToAdmins'`,
  
  rationale: 'Enabling security alert emails to subscription owners ensures that they receive security alert emails from Microsoft. This ensures that they are aware of any potential security issues and can mitigate the risk in a timely fashion.',
  
  remediation: `**From Azure Console**
  
  1. Go to Security Center
  2. Click on Pricing & settings
  3. Click on the appropriate Management Group, Subscription, or Workspace
  4. Click on Email notifications
  5. In the drop down of the All users with the following roles field select Owner
  6. Click Save
  
  **Using Azure Command Line Interface 2.0**  
  Use the below command to set Send email also to subscription owners to On.
  
          az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c 'curl -X PUT -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/securityContacts/default1?api-version=2017-08-01-preview -d@"input.json"'
  
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
          }`,
  
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
      alertsToAdmins
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
        path: '@.alertsToAdmins',
        equal: 'On',
      },
    ],
  },
}
