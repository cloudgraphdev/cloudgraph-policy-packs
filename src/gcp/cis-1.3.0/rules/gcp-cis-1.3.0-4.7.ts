export default {
  id: 'gcp-cis-1.3.0-4.7',
  title:
    'GCP CIS 4.7 Ensure VM disks for critical VMs are encrypted with Customer-Supplied Encryption Keys (CSEK)',
  description: `Customer-Supplied Encryption Keys (CSEK) are a feature in Google Cloud Storage and
  Google Compute Engine. If you supply your own encryption keys, Google uses your key to
  protect the Google-generated keys used to encrypt and decrypt your data. By default,
  Google Compute Engine encrypts all data at rest. Compute Engine handles and manages
  this encryption for you without any additional actions on your part. However, if you
  wanted to control and manage this encryption yourself, you can provide your own
  encryption keys.`,
  audit: `**From Console:**

  1. Go to Compute Engine *Disks* by visiting:
      https://console.cloud.google.com/compute/disks.
  2. Click on the disk for your critical VMs to see its configuration details.
  3. Ensure that *Encryption type* is set to *Customer supplied*.

  **From Command Line:**
  Ensure *diskEncryptionKey* property in the below command's response is not null, and
  contains key *sha256* with corresponding value

      gcloud compute disks describe DISK_NAME --zone ZONE -- format="json(diskEncryptionKey,name)"`,
  rationale: `By default, Google Compute Engine encrypts all data at rest. Compute Engine handles and manages this encryption for you without any additional actions on your part. However, if you wanted to control and manage this encryption yourself, you can provide your own encryption keys.

  If you provide your own encryption keys, Compute Engine uses your key to protect the Google-generated keys used to encrypt and decrypt your data. Only users who can provide the correct key can use resources protected by a customer-supplied encryption key.

  Google does not store your keys on its servers and cannot access your protected data unless you provide the key. This also means that if you forget or lose your key, there is no way for Google to recover the key or to recover any data encrypted with the lost key.

  At least business critical VMs should have VM disks encrypted with CSEK.`,
  remediation: `**Note:** Currently there is no way to update the encryption of an existing disk. Therefore you should create a new disk with *Encryption* set to *Customer supplied*.

  **From Console:**

  1. Go to Compute Engine *Disks* by visiting: https://console.cloud.google.com/compute/disks.
  2. Click *CREATE DISK*.
  3. Set *Encryption type* to *Customer supplied*.
  4. Provide the *Key* in the box.
  5. Select *Wrapped key*.
  6. Click *Create*.

  **From Command Line:**
  In the gcloud compute tool, encrypt a disk using the --csek-key-file flag during instance
  creation. If you are using an RSA-wrapped key, use the gcloud beta component:

      gcloud (beta) compute instances create INSTANCE_NAME --csek-key-file <example-file.json>


  To encrypt a standalone persistent disk:

      gcloud (beta) compute disks create DISK_NAME --csek-key-file <example- file.json`,
  references: [
    'https://cloud.google.com/compute/docs/disks/customer-supplied-encryption#encrypt_a_new_persistent_disk_with_your_own_keys',
    'https://cloud.google.com/compute/docs/reference/rest/v1/disks/get',
    'https://cloud.google.com/compute/docs/disks/customer-supplied-encryption#key_file',
  ],
  gql: `{
    querygcpVmInstance{
      __typename
      id
      disks{
        diskEncryptionKey{
          sha256
        }
      }
    }
  }`,
  resource: 'querygcpVmInstance[*]',
  severity: 'unknown',
  conditions: {
    path: '@.disks',
    array_any: {
      and: [
        {
          path: '[*].diskEncryptionKey',
          notEqual: null,
        },
        {
          path: '[*].diskEncryptionKey.sha256',
          isEmpty: false,
        },
      ],
    },
  },
}
