/* eslint-disable max-len */
export default {
  id: 'gcp-cis-1.2.0-7.1',  
  title: 'GCP CIS 7.1 Ensure that BigQuery datasets are not anonymously or publicly accessible',  
  description: 'It is recommended that the IAM policy on BigQuery datasets does not allow anonymous and/or public access.',  
  audit: `**From Console:**
  
  1. Go to BigQuery by visiting: https://console.cloud.google.com/bigquery.
  2. Select a dataset from Resources.
  3. Click SHARE DATASET near the right side of the window.
  4. Validate that none of the attached roles contain allUsers or allAuthenticatedUsers.
  
  **From Command Line:**
  
  1. Retrieve the data set information using the following command:
  
          bq show PROJECT_ID:DATASET_NAME
  
  2. Ensure that allUsers and allAuthenticatedUsers have not been granted access to the dataset.`,
  
  rationale: 'Granting permissions to allUsers or allAuthenticatedUsers allows anyone to access the dataset. Such access might not be desirable if sensitive data is being stored in the dataset. Therefore, ensure that anonymous and/or public access to a dataset is not allowed.',  
  remediation: `**From Console:**
  
  1. Go to BigQuery by visiting: https://console.cloud.google.com/bigquery.
  2. Select the dataset from 'Resources'.
  3. Click SHARE DATASET near the right side of the window.
  4. Review each attached role.
  5. Click the delete icon for each member allUsers or allAuthenticatedUsers. On the popup click Remove.
  
  **From Command Line:**
  
  1. Retrieve the data set information:
  
          bq show --format=prettyjson PROJECT_ID:DATASET_NAME > PATH_TO_FILE
  
  2. In the access section of the JSON file, update the dataset information to remove all roles containing allUsers or allAuthenticatedUsers.
  3. Update the dataset:
  
          bq update --source PATH_TO_FILE PROJECT_ID:DATASET_NAME`,  
  
  references: ['https://cloud.google.com/bigquery/docs/dataset-access-controls'],  
  gql: `{
    querygcpBigQueryDataset {
      id
      __typename
      access {
        role
      }
    }
  }`,
  resource: 'querygcpBigQueryDataset[*]',
  severity: 'high',
  conditions: {
    path: '@.access',
    array_any: {
      path: '[*].role',
      notIn: ['allUsers', 'allAuthenticatedUsers'],
    },
  },
}
