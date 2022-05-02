export default {
  id: 'azure-cis-1.3.1-2.13',  
  title: `Azure CIS 2.13 Ensure 'Additional email addresses' is configured with a security contact email`,  
  
  description: `Security Center emails the subscription owners whenever a high-severity alert is triggered
  for their subscription. You should provide a security contact email address as an additional
  email address.`,
  
  audit: `**From Azure Console**
  
  1. Go to Security Center
  2. Click on Pricing & settings
  3. Click on the appropriate Management Group, Subscription, or Workspace
  4. Click on Email notifications
  5. Ensure that a valid security contact email address is listed in the Additional email
  addresses field
  
  **Using Azure Command Line Interface 2.0**  
  Ensure the output of the below command is set not empty and is set with appropriate email ids.
  
    az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1
    bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/securityContacts?api-version=2017-08-01-preview' | jq '.|.value[] | select(.name=="default")'|jq '.properties.email'`,
  
  rationale: `Azure Security Center emails the Subscription Owner to notify them about security alerts.
  Adding your Security Contact's email address to the 'Additional email addresses' field
  ensures that your organization's Security Team is included in these alerts. This ensures
  that the proper people are aware of any potential compromise in order to mitigate the risk
  in a timely fashion.`,  
  
  remediation: `**From Azure Console**
  
  1. Go to Security Center
  2. Click on Pricing & settings
  3. Click on the appropriate Management Group, Subscription, or Workspace
  4. Click on Email notifications
  5. Enter a valid security contact email address (or multiple addresses separated by
  commas) in the Additional email addresses field
  6. Click Save

  **Using Azure Command Line Interface 2.0**  
  Use the below command to set Security contact emails to On.

    az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1
    bash -c 'curl -X PUT -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/securityContacts/default1?api-version=2017-08-01-preview -d@"input.json"'
  
  Where input.json contains the Request body json data as mentioned below. And replace validEmailAddress with email ids csv for multiple.

    {
      "id": "/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/securityContacts/default",
      "name": "default",
      "type": "Microsoft.Security/securityContacts",
      "properties": {
        "email": "<validEmailAddress>",
        "alertNotifications": "On",
        "alertsToAdmins": "On"
      }
    }

  **Default Value**:
  By default, there are no additional email addresses entered.`,
  
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
      email
    }
  }`,
  resource: 'queryazureSecurityContact[*]',
  severity: 'high',
  conditions: {
    and: [
      {
        path: '@.name',
        equal: 'default',
      },
      {
        path: '@.email',
        notIn: [null, ''],
      },
    ],
  },
}
