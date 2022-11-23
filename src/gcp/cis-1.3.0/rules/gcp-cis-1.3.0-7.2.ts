/* eslint-disable max-len */
export default {
  id: 'gcp-cis-1.3.0-7.2',
  title:
    'GCP CIS 7.2 Ensure that all BigQuery Tables are encrypted with Customer-managed encryption key (CMEK)',
  description:
    'BigQuery by default encrypts the data as rest by employing Envelope Encryption using Google managed cryptographic keys. The data is encrypted using the data encryption keys and data encryption keys themselves are further encrypted using key encryption keys. This is seamless and do not require any additional input from the user. However, if you want to have greater control, Customer-managed encryption keys (CMEK) can be used as encryption key management solution for BigQuery Data Sets. If CMEK is used, the CMEK is used to encrypt the data encryption keys instead of using google-managed encryption keys.',
  audit: `**From Console:**

  1. Go to Big Data
  2. Go to BigQuery
  3. Under Resources, select the project
  4. Select Data Set, select the table
  5. Go to Details tab
  6. Under Table info, verify Customer-managed key is present.
  7. Repeat for each table in all data sets for all projects.

  **From Command Line:**
  Use the following command to view the table details. Verify the kmsKeyName is present.

      bq show <table_object>`,

  rationale: `BigQuery by default encrypts the data as rest by employing Envelope Encryption using Google managed cryptographic keys. This is seamless and does not require any additional input from the user.

  For greater control over the encryption, customer-managed encryption keys (CMEK) can be used as encryption key management solution for BigQuery tables. The CMEK is used to encrypt the data encryption keys instead of using google-managed encryption keys. BigQuery stores the table and CMEK association and the encryption/decryption is done automatically.

  Applying the Default Customer-managed keys on BigQuery data sets ensures that all the new tables created in the future will be encrypted using CMEK but existing tables need to be updated to use CMEK individually.

      Note: Google does not store your keys on its servers and cannot access your protected data unless you provide the key. This also means that if you forget or lose your key, there is no way for Google to recover the key or to recover any data encrypted with the lost key.`,
  remediation: `Currently, there is no way to update the encryption of existing data in the table. The data needs to be copied to either an original table or another table while specifying the customer managed encryption key (CMEK).

  **From Command Line:**
  Use the following command to copy the data. The source and the destination needs to be same in case copying to the original table.

      bq cp --destination_kms_key <customer_managed_key>
      source_dataset.source_table destination_dataset.destination_table`,
  references: [
    'https://cloud.google.com/bigquery/docs/customer-managed-encryption',
  ],
  gql: `{
    querygcpBigQueryDataset {
      id
      __typename
      tables {
        encryptionConfigurationKmsKeyName
      }
    }
  }`,
  resource: 'querygcpBigQueryDataset[*]',
  severity: 'unknown',
  conditions: {
    path: '@.tables',
    array_any: {
      path: '[*].encryptionConfigurationKmsKeyName',
      isEmpty: false,
    },
  },
}
