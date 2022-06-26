export default {
  id: 'azure-nist-800-53-rev4-5.1',  
  title: 'Azure NIST 5.1 MySQL Database server firewall rules should not permit start and end IP addresses to be 0.0.0.0',
  
  description: 'Ensure that no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP).',
  
  audit: `** From Azure Console**
  
  1. Go to SQL servers
  2. For each SQL server
  3. Click on Firewall / Virtual Networks
  4. Ensure that Allow access to Azure services to set to OFF
  5. Ensure that no firewall rule exists with
  
      - Start IP of 0.0.0.0
      - or other combinations which allows access to wider public IP ranges
  
  **Using Azure PowerShell**  
  Get the list of all SQL Servers
  
      Get-AzureRmSqlServer
  
  For each Server
  
      Get-AzureRmSqlServerFirewallRule -ResourceGroupName <resource group name> -ServerName <server name>
  
  Ensure that StartIpAddress is not set to 0.0.0.0 or other combinations which allows access to wider public IP ranges including Windows Azure IP ranges.`,
  
  rationale: `SQL Server includes a firewall to block access to unauthorized connections. More granular IP addresses can be defined by referencing the range of addresses available from specific datacenters.
  
  By default, for a SQL server, a Firewall exists with StartIp of 0.0.0.0 and EndIP of 0.0.0.0 allowing access to all the Azure services.
  
  Additionally, a custom rule can be set up with StartIp of 0.0.0.0 and EndIP of 255.255.255.255 allowing access from ANY IP over the Internet.
  
  In order to reduce the potential attack surface for a SQL server, firewall rules should be defined with more granular IP addresses by referencing the range of addresses available from specific datacenters.`,
  
  remediation: `**From Azure Console**
  
  1. Go to SQL servers
  2. For each SQL server
  3. Click on Firewall / Virtual Networks
  4. Set Allow access to Azure services to 'OFF'
  5. Set firewall rules to limit access to only authorized connections
  
  **Using Azure PowerShell**  
  Disable Default Firewall Rule Allow access to Azure services:
  
      Remove-AzureRmSqlServerFirewallRule -FirewallRuleName "AllowAllWindowsAzureIps" -ResourceGroupName <resource group name> -ServerName <server name>
  
  Remove custom Firewall rule:
  
      Remove-AzureRmSqlServerFirewallRule -FirewallRuleName "<firewallRuleName>" -ResourceGroupName <resource group name> -ServerName <server name>
  
  Set the appropriate firewall rules:
  
      Set-AzureRmSqlServerFirewallRule -ResourceGroupName <resource group name> -ServerName <server name> -FirewallRuleName "<Fw rule Name>" -StartIpAddress "<IP Address other than 0.0.0.0>" -EndIpAddress "<IP Address other than 0.0.0.0 or 255.255.255.255>"`,
  
  references: [
      'https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-a-windows-firewall-for-database-engine-access?view=sql-server-2017',
      'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/get-azurermsqlserverfirewallrule?view=azurermps-5.2.0',
      'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/set-azurermsqlserverfirewallrule?view=azurermps-5.2.0',
      'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/remove-azurermsqlserverfirewallrule?view=azurermps-5.2.0',
      'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-firewall-configure',
      'https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-set-database-firewall-rule-azure-sql-database?view=azuresqldb-current',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-network-security#ns-1-implement-security-for-internal-traffic',
  ],    
  gql: `{
    queryazureSqlServer {
      id
      __typename
      firewallRules {
        startIpAddress
        endIpAddress
      }
    }
  }`,
  resource: 'queryazureSqlServer[*]',
  severity: 'high',
  conditions: {
    not: {
      path: '@.firewallRules',
      array_any: {
        or: [
          { 
            path: '[*].startIpAddress', 
            equal: '0.0.0.0' 
          },
          { 
            and: [
              {
                path: '[*].startIpAddress', 
                equal: '255.255.255.255' 
              },
              {
                path: '[*].endIpAddress', 
                equal: '0.0.0.0' 
              }
            ]
          },
        ],
      },
    },
  },
}
