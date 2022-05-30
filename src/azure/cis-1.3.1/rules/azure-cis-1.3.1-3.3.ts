export default {
  id: 'azure-cis-1.3.1-3.3',  
  title: 'Azure CIS 3.3 Ensure Storage logging is enabled for Queue service for read, write, and delete requests',
  
  description: 'The Storage Queue service stores messages that may be read by any client who has access to the storage account. A queue can contain an unlimited number of messages, each of which can be up to 64KB in size using version 2011-08-18 or newer. Storage Logging happens server-side and allows details for both successful and failed requests to be recorded in the storage account. These logs allow users to see the details of read, write, and delete operations against the queues. Storage Logging log entries contain the following information about individual requests: Timing information such as start time, end-to-end latency, and server latency, authentication details , concurrency information and the sizes of the request and response messages.',
  
  audit: `**From Azure Console:**
  
  1. Go to Storage Accounts.
  2. Select the specific Storage Account.
  3. Click the Diagnostics settings (classic) blade from Monitoring (classic) section.
  4. Ensure the Status is set to On, if set to Off.
  5. Select Queue properties.
  6. Ensure Read Write Delete options are selected under the Logging section.
  
  **Using Azure Command Line Interface 2.0:**  
  Ensure the below command's output contains properties delete, read and write set to true.
  
      az storage logging show --services q --account-name <storageAccountName>`,
  
  rationale: `Storage Analytics logs contain detailed information about successful and failed requests to a storage service. This information can be used to monitor individual requests and to diagnose issues with a storage service. Requests are logged on a best-effort basis.
  
  Storage Analytics logging is not enabled by default for your storage account.`,
  
  remediation: `**From Azure Console:**
  
  1. Go to Storage Accounts.
  2. Select the specific Storage Account.
  3. Click the Diagnostics settings (classic) blade from Monitoring (classic) section.
  4. Set the Status to On, if set to Off.
  5. Select Queue properties.
  6. Select Read, Write and Delete options under the Logging section to enable Storage Logging for Queue service.
  
  **Using Azure Command Line Interface 2.0**  
  Use the below command to enable the Storage Logging for Queue service.
  
      az storage logging update --account-name <storageAccountName> --account-key <storageAccountKey> --services q --log rwd --retention 90`,
  
  references: [
      'https://docs.microsoft.com/en-us/rest/api/storageservices/about-storage-analytics-logging',
      'https://docs.microsoft.com/en-us/cli/azure/storage/logging?view=azure-cli-latest',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-4-enable-logging-for-azure-resources',
  ],
  gql: `{
    queryazureStorageAccount {
      id
      __typename
      queueServiceProperties {
        logging {
          read
          write
          delete
        }
      }   
    }
  }`,
  resource: 'queryazureStorageAccount[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.queueServiceProperties.logging.read',
        equal: true,
      },
      {
        path: '@.queueServiceProperties.logging.write',
        equal: true,
      },
      {
        path: '@.queueServiceProperties.logging.delete',
        equal: true,
      },
    ],
  },
}
