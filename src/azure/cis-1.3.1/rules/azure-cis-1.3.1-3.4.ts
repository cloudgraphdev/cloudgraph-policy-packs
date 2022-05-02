export default {
  id: 'azure-cis-1.3.1-3.4',  
  title:
    'Azure CIS 3.4 Ensure that shared access signature tokens expire within an hour (Manual)',

  description: 'Expire shared access signature tokens within an hour.',

  audit:
    'Currently, SAS token expiration times cannot be audited. Until Microsoft makes token expiration time a setting rather than a token creation parameter, this recommendation would require a manual verification.',

  rationale:
    'A shared access signature (SAS) is a URI that grants restricted access rights to Azure Storage resources. A shared access signature can be provided to clients who should not be trusted with the storage account key but for whom it may be necessary to delegate access to certain storage account resources. Providing a shared access signature URI to these clients allows them access to a resource for a specified period of time. This time should be set as low as possible and preferably no longer than an hour.',

  remediation: `When generating shared access signature tokens, use start and end time such that it falls within an hour.
    
    **From Azure Console**
    
    1. Go to Storage Accounts
    2. For each storage account, go to Shared access signature
    3. Set Start and expiry date/time within an hour
    
    **note** At this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation.`,

  references: [
    'https://docs.microsoft.com/en-us/rest/api/storageservices/delegating-access-with-a-shared-access-signature',
  ],  
  severity: 'high',
}
