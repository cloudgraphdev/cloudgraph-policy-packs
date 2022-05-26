//GCP CIS 1.2.0 Rule equivalent 1.9
export default {
  id: 'gcp-pci-dss-3.2.1-6.1',
  title: 'KMS keys should not be anonymously or publicly accessible',
  
  description: 'It is recommended that the IAM policy on Cloud KMS cryptokeys should restrict anonymous and/or public access.',
  audit: `**From Command Line:**

  1. List all Cloud KMS Cryptokeys:
  
            gcloud kms keys list --keyring=[key_ring_name] --location=global --format=json | jq '.[].name'
  
  2. Ensure the below command's output does not contain allUsers and allAuthenticatedUsers:

            gcloud kms keys get-iam-policy [key_name] --keyring=[key_ring_name] --location=global --format=json | jq '.bindings[].members[]'`,  

  rationale: 'Granting permissions to allUsers or allAuthenticatedUsers allows anyone to access the dataset. Such access might not be desirable if sensitive data is stored at the location. In this case, ensure that anonymous and/or public access to a Cloud KMS cryptokey is not allowed.',

  remediation: `**From Command Line:**

  1. List all Cloud KMS Cryptokeys

        gcloud kms keys list --keyring=[key_ring_name] --location=global --format=json | jq '.[].name'

  2. Remove IAM policy binding for a KMS key to remove access to allUsers and allAuthenticatedUsers using the below command
  
        gcloud kms keys remove-iam-policy-binding [key_name] --keyring=[key_ring_name] --location=global --member='allAuthenticatedUsers' --role='[role]'

        gcloud kms keys remove-iam-policy-binding [key_name] --keyring=[key_ring_name] --location=global --member='allUsers' --role='[role]'`,

  references: [
    'https://cloud.google.com/sdk/gcloud/reference/kms/keys/remove-iam-policy-binding',
    'https://cloud.google.com/sdk/gcloud/reference/kms/keys/set-iam-policy',
    'https://cloud.google.com/sdk/gcloud/reference/kms/keys/get-iam-policy',
    'https://cloud.google.com/kms/docs/object-hierarchy#key_resource_id',
  ],
  gql: `{
    querygcpKmsKeyRing {
      id
      __typename
      kmsCryptoKeys {
        iamPolicy {
          bindings {
            members
          }
        }
      }
    }
  }`,
  resource: 'querygcpKmsKeyRing[*]',
  severity: 'high',
  conditions: {
    not: {
      path: '@.kmsCryptoKeys',
      array_any: {
        path: '[*].iamPolicy',
        array_any: {
          path: '[*].bindings',
          array_any: {
            or: [
              {
                path: '[*].members',
                match: /allUsers.*$/,
              },
              {
                path: '[*].members',
                match: /allAuthenticatedUsers.*$/,
              },
            ],
          },
        },
      },
    },
  },
}