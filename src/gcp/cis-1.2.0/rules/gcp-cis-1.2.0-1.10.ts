/* eslint-disable max-len */
export default {
  id: 'gcp-cis-1.2.0-1.10',  
  title: 'GCP CIS 1.10 Ensure KMS encryption keys are rotated within a period of 90 days',  
  
  description:`Google Cloud Key Management Service stores cryptographic keys in a hierarchical structure designed for useful and elegant access control management.
  
  The format for the rotation schedule depends on the client library that is used. For the gcloud command-line tool, the next rotation time must be in ISO or RFC3339 format, and the rotation period must be in the form INTEGER[UNIT], where units can be one of seconds (s), minutes (m), hours (h) or days (d).`,  
  
  audit: `**From Console:**
  
  1. Go to Cryptographic Keys by visiting https://console.cloud.google.com/security/kms
  
  2. Click on each key ring, then ensure each key in the keyring has Next Rotation set for less than 90 days from the current date.
  
          gcloud kms keys get-iam-policy [key_name] --keyring=[key_ring_name] --location=global --format=json | jq '.bindings[].members[]',
  
  **From Command Line:**
  
  1. Ensure rotation is scheduled by ROTATION_PERIOD and NEXT_ROTATION_TIME for each key :
  
          gcloud kms keys list --keyring=<KEY_RING> --location= --format=json'(rotationPeriod)'
  
      Ensure outcome values for rotationPeriod and nextRotationTime satisfy the below criteria:
  
          rotationPeriod is <= 129600m
  
          rotationPeriod is <= 7776000s
  
          rotationPeriod is <= 2160h
  
          rotationPeriod is <= 90d
  
          nextRotationTime is <= 90days from current DATE,`,
  
  rationale: `Set a key rotation period and starting time. A key can be created with a specified rotation
  period, which is the time between when new key versions are generated automatically. A
  key can also be created with a specified next rotation time. A key is a named object
  representing a cryptographic key used for a specific purpose. The key material, the actual
  bits used for encryption, can change over time as new key versions are created.
  
  A key is used to protect some corpus of data. A collection of files could be encrypted with
  the same key and people with decrypt permissions on that key would be able to decrypt
  those files. Therefore, it's necessary to make sure the rotation period is set to a specific
  time.`,
  
  remediation: `**From Console:**
  
  1. Go to Cryptographic Keys by visiting: https://console.cloud.google.com/security/kms.
  
  2. Click on the specific key ring
  
  3. From the list of keys, choose the specific key and Click on Right side pop up the blade (3 dots)
  
  4. Click on Edit rotation period.
  
  5. On the pop-up window, Select a new rotation period in days which should be less than 90 and then choose Starting on date (date from which the rotation period begins).
  
  **From Command Line:**
  
  1. Update and schedule rotation by ROTATION_PERIOD and NEXT_ROTATION_TIME for each key:
  
          gcloud kms keys update new --keyring=KEY_RING --location=LOCATION --next-rotation-time=NEXT_ROTATION_TIME --rotation-period=ROTATION_PERIOD`,
  
  references: ['https://cloud.google.com/kms/docs/key-rotation#frequency_of_key_rotation','https://cloud.google.com/kms/docs/re-encrypt-data'],
  gql: `{
    querygcpKmsKeyRing { 
      id 
      __typename
      kmsCryptoKeys {
        rotationPeriod
        nextRotationTime
      }
     }
  }`,
  resource: 'querygcpKmsKeyRing[*]',
  severity: 'unknown',
  conditions: {
    path: '@.kmsCryptoKeys',
    array_any: {
      and: [
        {
          path: '[*].rotationPeriod',
          lessThanInclusive: 7776000,
        },
        {
          value: { daysDiff: {}, path: '[*].nextRotationTime' },
          lessThanInclusive: 90,
        },
      ]
    },
  },
}
