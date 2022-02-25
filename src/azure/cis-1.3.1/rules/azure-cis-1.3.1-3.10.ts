export default {
  id: 'azure-cis-1.3.1-3.10',  
  title: 'Azure CIS 3.10 Ensure Storage logging is enabled for Blob service for read, write, and delete requests (Manual)',
  
  description: 'The Storage Blob service provides scalable, cost-efficient objective storage in the cloud. Storage Logging happens server-side and allows details for both successful and failed requests to be recorded in the storage account. These logs allow users to see the details of read, write, and delete operations against the blobs. Storage Logging log entries contain the following information about individual requests: Timing information such as start time, end-to-end latency, and server latency, authentication details , concurrency information and the sizes of the request and response messages.',
  
  audit: `**From Azure Console:**
  
  - Go to Storage Accounts.
  - Select the specific Storage Account.
  - Click the Diagnostics settings (classic) blade from Monitoring (classic) section.
  - Ensure the Status is set to On, if set to Off.
  - Select Blob properties.
  - Ensure Read, Write, and Delete options are selected under the Logging section.
  
  **Using Azure Command Line Interface:**  
  Ensure the below command's output contains properties delete, read and write set to true.
  
      az storage logging show --services b --account-name <storageAccountName>`,
  
  rationale: 'Storage Analytics logs contain detailed information about successful and failed requests to a storage service. This information can be used to monitor individual requests and to diagnose issues with a storage service. Requests are logged on a best-effort basis.',
  
  remediation: `**From Azure Console:**
  
  - Go to Storage Accounts.
  - Select the specific Storage Account.
  - Click the Diagnostics settings (classic) blade from Monitoring (classic) section.
  - Set the Status to On, if set to Off.
  - Select Blob properties.
  - Select Read, Write and Delete options under the Loggingsection to enable Storage Logging for Blob service.
  
  **Using Azure Command Line Interface:**  
  Use the below command to enable the Storage Logging for Blob service.
  
      az storage logging update --account-name <storageAccountName> --account-key <storageAccountKey> --services b --log rwd --retention 90`,
  
  references: [
      'https://docs.microsoft.com/en-us/rest/api/storageservices/about-storage-analytics-logging',
      'https://docs.microsoft.com/en-us/cli/azure/storage/logging?view=azure-cli-latest',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-4-enable-logging-for-azure-resources',
  ],  
  severity: 'medium',
}
