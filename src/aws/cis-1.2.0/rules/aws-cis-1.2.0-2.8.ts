export default {
  id: 'aws-cis-1.2.0-2.8',
  title:
    'AWS CIS 2.8 Ensure rotation for customer created CMKs is enabled (Scored)',
  description: `AWS Key Management Service (KMS) allows customers to rotate the backing key which is
  key material stored within the KMS which is tied to the key ID of the Customer Created
  customer master key (CMK). It is the backing key that is used to perform cryptographic
  operations such as encryption and decryption. Automated key rotation currently retains all
  prior backing keys so that decryption of encrypted data can take place transparently. It is
  recommended that CMK key rotation be enabled.`,
  audit: `Via the Management Console:

  1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam.
  2. In the left navigation pane, choose E*ncryption Keys*.
  3. Select a customer created master key (CMK)
  4. Under the *Key Policy* section, move down to *Key Rotation*.
  5. Ensure the *Rotate this key every year* checkbox is checked.

  Via CLI

  1. Run the following command to get a list of all keys and their associated *KeyIds*

    aws kms list-keys

  2. For each key, note the KeyId and run the following command

    aws kms get-key-rotation-status --key-id <kms_key_id>

  3. Ensure *KeyRotationEnabled* is set to *true*`,
  rationale: `Rotating encryption keys helps reduce the potential impact of a compromised key as data encrypted with a new key cannot be accessed with a previous key that may have been exposed.`,
  remediation: `Via the Management Console:

  1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam.
  2. In the left navigation pane, choose *Encryption Keys*.
  3. Select a customer created master key (CMK)
  4. Under the *Key Policy* section, move down to *Key Rotation*.
  5. Check the *Rotate this key every year* checkbox.

  Via CLI

  1. Run the following command to enable key rotation:

    aws kms enable-key-rotation --key-id <kms_key_id>`,
  references: [
    `https://aws.amazon.com/kms/pricing/`,
    `http://csrc.nist.gov/publications/nistpubs/800-57/sp800-](http://csrc.nist.gov/publications/nistpubs/800-57/sp800-57_part1_rev3_general.pdf`,
    `CCE- 78920 - 6`,
  ],
  gql: `{
    queryawsKms {
      id
      __typename
      keyManager
      keyRotationEnabled
    }
  }`,
  resource: 'queryawsKms[*]',
  severity: 'medium',
  conditions: {
    or: [
      {
        and: [
          {
            path: '@.keyManager',
            equal: 'AWS',
          },
          {
            path: '@.keyRotationEnabled',
            equal: 'Yes',
          },
        ],
      },
      {
        and: [
          {
            path: '@.keyManager',
            equal: 'CUSTOMER',
          },
          {
            path: '@.keyRotationEnabled',
            equal: 'Yes',
          },
        ],
      },
    ],
  },
}
