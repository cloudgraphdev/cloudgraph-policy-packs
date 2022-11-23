export default {
  id: 'pci-dss-3.2.1-threat-mitigation-check-1',  
  title: 'Threat Mitigation Check 1: Ensure Azure Application Gateway Web application firewall (WAF) is enabled',
  
  description: 'Ensure Azure Application Gateway Web application firewall (WAF) is enabled. Azure Application Gateway offers a web application firewall (WAF) that provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**From Azure Console**
  
  1. Login to Azure Portal using https://portal.azure.com
  2. Navigate to your Application Gateway
  3. Under Settings, select Web application firewall
  4. Under the Configure tab:
    a. Ensure Tier is set to WAF
    b. Ensure Firewall status is set to Enabled
    c. Select the appropriate Firewall mode to your requirements
  5. Under the Rules tab:
    a. Select the appropriate Rule set according to your requirements
  6. Click Save
  
  Using Azure Command Line Interface to update an existing Application Gateway to enable WAF configuration:

      az network application-gateway update \
        --resource-group <RESOURCE_GROUP_NAME> \
        --name <APPLICATION_GATEWAY_NAME> \
        --sku <WAF_Large|WAF_Medium|WAF_v2>

      az network application-gateway waf-config set \
        --resource-group <RESOURCE_GROUP_NAME> \
        --gateway-name <APPLICATION_GATEWAY_NAME> \
        --enabled true \
        --firewall-mode <Detection|Prevention> \
        --rule-set-version 3.0
  `,
  
  references: [
    'https://docs.microsoft.com/en-us/azure/application-gateway/waf-overview',
    'https://docs.microsoft.com/en-us/cli/azure/network/application-gateway?view=azure-cli-latest',
    'https://docs.microsoft.com/en-us/cli/azure/network/application-gateway/waf-config?view=azure-cli-latest#az-network-application-gateway-waf-config-set',
  ],
  gql: `{
    queryazureApplicationGateway {
      id
      __typename
      webApplicationFirewallConfiguration {
        enabled
      }
    }
  }`,
  resource: 'queryazureApplicationGateway[*]',
  severity: 'medium',
  conditions: {
    path: '@.webApplicationFirewallConfiguration.enabled',
    equal: true,
  },
}
