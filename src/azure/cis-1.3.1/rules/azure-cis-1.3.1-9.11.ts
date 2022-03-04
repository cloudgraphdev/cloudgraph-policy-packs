export default {
  id: 'azure-cis-1.3.1-9.11',  
  title:
    'Azure CIS 9.11 Ensure Azure Keyvaults are used to store secrets (Manual)',

  description:
    'Encryption keys ,Certificate thumbprints and Managed Identity Credentials can be coded into the APP service, this renders them visible as part of the configuration, to maintain security of these keys it is better to store in an Azure Keyvault and reference them from the Keyvault.',

  audit: `**From Azure Console**
    
    1. Login to Azure Portal using https://portal.azure.com
    2. Go to Key Vaults
    3. Ensure that key vault exists and keys are listed`,

  rationale:
    'App secrets control access to the application and thus need to be secured externally to the app configuration, storing the secrets externally and referencing them in the configuration also enables key rotation without having to redeploy the app service.',

  remediation: `Remediation has 2 steps
    
    1. Setup the keyvault
    2. setup the app service to use the keyvault
    
    **Set up the keyvault**
    **Using Azure CLI**
    
        az keyvault create --name "myKV" --resource-group "myResourceGroup" --location myLocation
    
    **Using Azure Powershell**
    
        New-AzKeyvault -name MyKV -ResourceGroupName myResourceGroup -Location myLocation
    
    **Set up the App Service to use the keyvault**  
    Sample JSON Template for App Service Configuration
    
        { 
            //...
            "resources": [
                { 
                    "type": "Microsoft.Storage/storageAccounts",
                    "name": "[variables('storageAccountName')]",
                    //...
                }, 
                { 
                    "type": "Microsoft.Insights/components",
                    "name": "[variables('appInsightsName')]",
                    //...
                },
                { 
                    "type": "Microsoft.Web/sites",
                    "name": "[variables('functionAppName')]",
                    "identity": {
                        "type": "SystemAssigned" 
                    },
                    //...
                    "resources": [
                        { 
                            "type": "config",
                            "name": "appsettings",
                            //...
                            "dependsOn": [
                                "[resourceId('Microsoft.Web/sites', variables('functionAppName'))]",
                                "[resourceId('Microsoft.KeyVault/vaults/', variables('keyVaultName'))]",
                                "[resourceId('Microsoft.KeyVault/vaults/secrets', variables('keyVaultName'), variables('storageConnectionStringName'))]",
                                "[resourceId('Microsoft.KeyVault/vaults/secrets', variables('keyVaultName'), variables('appInsightsKeyName'))]" ],
                                "properties": { 
                                    "AzureWebJobsStorage": "[concat('@Microsoft.KeyVault(SecretUri=', reference(variables('storageConnectionStringResourceId')).secretUriWithVersion, ')')]",
                                    "WEBSITE_CONTENTAZUREFILECONNECTIONSTRING": "[concat('@Microsoft.KeyVault(SecretUri=', reference(variables('storageConnectionStringResourceId')).secretUriWithVersion, ')')]",
                                    "APPINSIGHTS_INSTRUMENTATIONKEY": "[concat('@Microsoft.KeyVault(SecretUri=', reference(variables('appInsightsKeyResourceId')).secretUriWithVersion, ')')]",
                                    "WEBSITE_ENABLE_SYNC_UPDATE_SITE": "true" //...
                                }
                            },
                            { 
                                "type": "sourcecontrols",
                                "name": "web",
                                //...
                                "dependsOn": [
                                    "[resourceId('Microsoft.Web/sites', variables('functionAppName'))]",
                                    "[resourceId('Microsoft.Web/sites/config', variables('functionAppName'), 'appsettings')]"
                                ],
                            }
                        ] 
                    }, 
                    { 
                        "type": "Microsoft.KeyVault/vaults",
                        "name": "[variables('keyVaultName')]",
                        //...
                        "dependsOn": [
                            "[resourceId('Microsoft.Web/sites', variables('functionAppName'))]"
                        ],
                        "properties": {
                            //...
                            "accessPolicies": [
                                { "tenantId": "[reference(concat('Microsoft.Web/sites/', variables('functionAppName'), '/providers/Microsoft.ManagedIdentity/Identities/default'), '2015-08-31-PREVIEW').tenantId]",
                                "objectId": "[reference(concat('Microsoft.Web/sites/', variables('functionAppName'), '/providers/Microsoft.ManagedIdentity/Identities/default'), '2015-08-31-PREVIEW').principalId]",
                                "permissions": {
                                    "secrets": [ "get" ]
                                }
                            }
                        ]
                    },
                    "resources": [
                        {
                            "type": "secrets",
                            "name": "[variables('storageConnectionStringName')]",
                            //...
                            "dependsOn": [
                                "[resourceId('Microsoft.KeyVault/vaults/', variables('keyVaultName'))]",
                                "[resourceId('Microsoft.Storage/storageAccounts', variables('storageAccountName'))]"
                            ],
                            "properties": {
                                "value": "[concat('DefaultEndpointsProtocol=https;AccountName=', variables('storageAccountName'), ';AccountKey=', listKeys(variables('storageAccountResourceId'),'2015-05-01-preview').key1)]"
                            }
                        },
                        { 
                            "type": "secrets",
                            "name": "[variables('appInsightsKeyName')]",
                            //...
                            "dependsOn": [
                                "[resourceId('Microsoft.KeyVault/vaults/', variables('keyVaultName'))]",
                                "[resourceId('Microsoft.Insights/components', variables('appInsightsName'))]"
                            ],
                            "properties": {
                                "value": "[reference(resourceId('microsoft.insights/components/', variables('appInsightsName')), '2015-05-01').InstrumentationKey]"
                            }
                        }
                    ]
                }
            ]
        }`,

  references: [
    'https://docs.microsoft.com/en-us/azure/app-service/app-service-key-vault-references',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-identity-management#im-2-manage-application-identities-securely-and-automatically',
  ],  
  severity: 'high',
}
