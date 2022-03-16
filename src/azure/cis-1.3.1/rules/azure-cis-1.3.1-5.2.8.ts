export default {
  id: 'azure-cis-1.3.1-5.2.8',  
  title: 'Azure CIS 5.2.8 Ensure that Activity Log Alert exists for Delete Security Solution',
  
  description: `Create an activity log alert for the Delete Security Solution event.`,
  
  audit: `**From Azure Console:**
  
  1. Navigate to Monitor' / 'Alerts
  2. Select Manage alert rules
  3. Click on the Alert Name where Condition contains operationName equals
  Microsoft.Security/securitySolutions/delete
  4. Hover a mouse over Condition to ensure it is set to Whenever the Administrative
  Activity Log "Delete Security Solutions (securitySolutions)" has "any"
  level with "any" status and event is initiated by "any"
  
  **Using Azure Command Line Interface**  
    
    az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1
    bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/providers/microsoft.insights/activityLogAlerts?api-version=2017-04-01' | jq '.|.value[]|{location:.location,scopes:.properties.scopes,"condition":.properties.condition.allOf|.[]|select(.field=="operationName" and .equals=="microsoft.security/securitysolutions/delete"),enabled:.properties.enabled}'
    
  Ensure that an alert exists where:
  - location is set to Global
  - Scopes is set to entire subscription that is /subscriptions/<Subscription_ID>
  - Enabled set to True
  - Condition Matches:
  
    {
      "location": "Global",
      "scopes": [
        "/subscriptions/<Subscription_ID>"
      ],
      "condition": {
        "field": "operationName",
        "equals": "microsoft.security/securitysolutions/delete",
        "containsAny": null
      },
      "enabled": true
    }`,
  
  rationale: `Monitoring for Delete Security Solution events gives insight into changes to the active
  security solutions and may reduce the time it takes to detect suspicious activity.`,
  
  remediation: `**From Azure Console:**
  
  1. Go to Monitor
  2. Select Alerts
  3. Click On New Alert Rule
  4. Under Scope, click Select resource
  5. Select the appropriate subscription under Filter by subscription
  6. Select Security Solutions under Filter by resource type
  7. Select All for Filter by location
  8. Click on the subscription resource from the entries populated under Resource
  9. Click Done
  10. Verify Selection preview shows Security Solutions and your selected subscription name
  11. Under Condition click Add Condition
  12. Select Delete Security Solutions signal
  13. Click Done
  14. Under Action group, select Add action groups and complete creation process or select appropriate action group
  15. Under Alert rule details, enter Alert rule name and Description
  16. Select appropriate resource group to save the alert to
  17. Check Enable alert rule upon creation checkbox
  18. Click Create alert rule
  
  **Using Azure Command Line Interface**  
  Use the below command to create an Activity Log Alert for Delete Security Solutions
  
    az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1
    bash -c 'curl -X PUT -H "Authorization: Bearer $1" -H "Content-Type:application/json" https://management.azure.com/subscriptions/$0/resourceGroups/<Resource_Group_ToCreate_Alert_In>/providers/microsoft.insights/activityLogAlerts/<Unique_Alert_Name>?api-version=2017-04-01 -d@"input.json"'
    
  Where input.json contains the Request body JSON data as mentioned below.

    {
      "location": "Global",
      "tags": {},
      "properties": {
        "scopes": [
          "/subscriptions/<Subscription_ID>"
        ],
        "enabled": true,
        "condition": {
          "allOf": [
          {
            "containsAny": null,
            "equals": "Security",
            "field": "category"
          },
          {
            "containsAny": null,
            "equals": "Microsoft.Security/securitySolutions/delete",
            "field": "operationName"
          }
          ]
        },
        "actions": {
          "actionGroups": [
          {
            "actionGroupId": "/subscriptions/<Subscription_ID>/resourceGroups/<Resource_Group_For_Alert_Group>/providers/microsoft.insights/actionGroups/<Alert_Group>",
            "webhookProperties": null
          }
          ]
        },
      }
    }

  Configurable Parameters for command line:

    <Resource_Group_To Create_Alert_In>
    <Unique_Alert_Name>

  Configurable Parameters for input.json:

    <Subscription_ID> in scopes
    <Subscription_ID> in actionGroupId
    <Resource_Group_For_Alert_Group> in actionGroupId
    <Alert_Group> in actionGroupId`,
  
  references: [
    'https://azure.microsoft.com/en-us/updates/classic-alerting-monitoring-retirement',
    'https://docs.microsoft.com/en-in/azure/azure-monitor/platform/alerts-activity-log',
    'https://docs.microsoft.com/en-in/rest/api/monitor/activitylogalerts/createorupdate',
    'https://docs.microsoft.com/en-in/rest/api/monitor/activitylogalerts/listbysubscriptionid',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-4-enable-logging-for-azure-resources'
  ],  
  gql: `{
    queryazureActivityLogAlert {
      id
      __typename
      name
      region
      enabled
      condition {
        allOf {
          field
          equals
        }
      }
    }
  }`,
  resource: 'queryazureActivityLogAlert[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.region',
        equal: 'global',
      },
      {
        path: '@.enabled',
        equal: true,
      },
      {
        path: '@.condition.allOf',
        array_any: {
          and: [
          {
            path: '[*].field',
            equal: 'operationName',
          },
          {
            path: '[*].equals',
            equal: 'microsoft.security/securitysolutions/delete',
          }]
        },
      }
    ],
  },
}