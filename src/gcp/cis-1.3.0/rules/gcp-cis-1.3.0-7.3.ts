/* eslint-disable max-len */
export default {
  id: 'gcp-cis-1.3.0-7.3',
  title:
    'GCP CIS 7.3 Ensure that a Default Customer-managed encryption key (CMEK) is specified for all BigQuery Data Sets',
  description:
    'BigQuery by default encrypts the data as rest by employing Envelope Encryption using Google managed cryptographic keys. The data is encrypted using the data encryption keys and data encryption keys themselves are further encrypted using key encryption keys. This is seamless and do not require any additional input from the user. However, if you want to have greater control, Customer-managed encryption keys (CMEK) can be used as encryption key management solution for BigQuery Data Sets.',
  audit: `**From Console:**

  1. Go to Big Data
  2. Go to BigQuery
  3. Under Resources, select the project
  4. Select Data Set
  5. Ensure Customer-managed key is present under Dataset info section.
  6. Repeat for each data set in all projects.

  **From Command Line:**
  Use the following command to view the data set details. Verify the kmsKeyName is present.,

      bq show <data_set_object>`,
  rationale: `BigQuery by default encrypts the data as rest by employing Envelope Encryption using Google managed cryptographic keys. This is seamless and does not require any additional input from the user.

  For greater control over the encryption, customer-managed encryption keys (CMEK) can be used as encryption key management solution for BigQuery Data Sets. Setting a Default Customer-managed encryption key (CMEK) for a data set ensure any tables created in future will use the specified CMEK if none other is provided.

      Note: Google does not store your keys on its servers and cannot access your protected data unless you provide the key. This also means that if you forget or lose your key, there is no way for Google to recover the key or to recover any data encrypted with the lost key.`,
  remediation:
    'The default CMEK for existing data sets can be updated by specifying the default key in the EncryptionConfiguration.kmsKeyName field when calling the datasets.insert or datasets.patch methods.',
  references: [
    'https://cloud.google.com/bigquery/docs/customer-managed-encryption',
  ],
  gql: `{
    querygcpBigQueryDataset {
      id
      __typename
      defaultEncryptionConfiguration {
        kmsKeyName
      }
    }
  }`,
  resource: 'querygcpBigQueryDataset[*]',
  severity: 'unknown',
  conditions: {
    path: '@.defaultEncryptionConfiguration.kmsKeyName',
    isEmpty: false,
  },
}
