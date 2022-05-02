export default {
  id: 'azure-cis-1.3.1-1.23',  
  title: 'Azure CIS 1.23 Ensure Custom Role is assigned for Administering Resource Locks (Manual)',  
  
  description: 'Resource locking is a powerful protection mechanism that can prevent inadvertent modification/deletion of resources within Azure subscriptions/Resource Groups and is a recommended NIST configuration.',
  
  audit: `**From Azure Console**
  
  1. In the Azure portal, open a subscription or resource group where you want the view assigned roles.
  2. Select Access control (IAM)
  3. Select Roles
  4. Search for the custom role named <role_name> Ex. from remediation "Resource Lock Administrator"
  5. ensure that the role is assigned the appropriate user/users`,
  
  rationale: 'Given the resource lock functionality is outside of standard Role Based Access Control(RBAC), it would be prudent to create a resource lock administrator role to prevent inadvertent unlocking of resources.',  
  
  remediation: `**From Azure Console**
  
  1. In the Azure portal, open a subscription or resource group where you want the custom role to be assignable.
  2. Select Access control (IAM)
  3. Click Add
  4. Select Add custom role.
  5. In the Custom Role Name field enter Resource Lock Administrator
  6. In the Description field enter Can Administer Resource Locks
  7. For Baseline permissions select Start from scratch
  8. Click next
  9. In the Permissions tab select Add permissions
  10. in the Search for a permission box, type in Microsoft.Authorization/locks to search for permissions.
  11. Select the check box next to the permission called Microsoft.Authorization/locks
  12. click add
  13. Click Review+create
  14. Click Create
  
  Assign the newly created role to the appropriate user.
  
  **Using PowerShell:**  
  Below is a power shell definition for a resource lock administrator role created at an Azure Management group level
  
      Import-Module Az.Accounts
      Connect-AzAccount
      
      $role = Get-AzRoleDefinition "User Access Administrator"
      $role.Id = $null
      $role.Name = "Resource Lock Administrator"
      $role.Description = "Can Administer Resource Locks"
      $role.Actions.Clear()
      $role.Actions.Add("Microsoft.Authorization/locks/*")
      $role.AssignableScopes.Clear() 
      
      * Scope at the Management group level Management group
      
      $role.AssignableScopes.Add("/providers/Microsoft.Management/managementGroups/MG-Name")
      
      New-AzRoleDefinition -Role $role Get-AzureRmRoleDefinition "Resource Lock Administrator"`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/role-based-access-control/custom-roles',
      'https://docs.microsoft.com/en-us/azure/role-based-access-control/check-access',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-1-protect-and-limit-highly-privileged-users',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-2-restrict-administrative-access-to-business-critical-systems',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-7-follow-just-enough-administration-least-privilege-principle',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-5-automate-entitlement-management',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
  ],  
  severity: 'high',
}
