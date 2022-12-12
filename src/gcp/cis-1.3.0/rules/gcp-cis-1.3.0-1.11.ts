/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
/* eslint-disable @typescript-eslint/no-explicit-any */
export default {
  id: 'gcp-cis-1.3.0-1.11',
  title:
    'GCP CIS 1.11 Ensure that Separation of duties is enforced while assigning KMS related roles to users',

  description:
    'It is recommended that the principle of "Separation of Duties" is enforced while assigning KMS related roles to users.',

  audit: `**From Console:**

  1. Go to IAM & Admin/IAM by visiting https://console.cloud.google.com/iam-admin/iam
  
  2. Ensure no member has the roles Cloud KMS Admin and any of the Cloud KMS CryptoKey Encrypter/Decrypter, Cloud KMS CryptoKey Encrypter, Cloud KMS CryptoKey Decrypter assigned.
  
  **From Command Line:**
  
  1. List all users and role assignments:
  
          gcloud projects get-iam-policy PROJECT_ID
  
  2. Ensure that there are no common users found in the member section for roles cloudkms.admin and any one of Cloud KMS CryptoKey Encrypter/Decrypter, Cloud KMS CryptoKey Encrypter, Cloud KMS CryptoKey Decrypter`,

  rationale: `The built-in/predefined IAM role Cloud KMS Admin allows the user/identity to create, delete, and manage service account(s). The built-in/predefined IAM role Cloud KMS CryptoKey Encrypter/Decrypter allows the user/identity (with adequate privileges on concerned resources) to encrypt and decrypt data at rest using an encryption key(s).
  
  The built-in/predefined IAM role Cloud KMS CryptoKey Encrypter allows the user/identity (with adequate privileges on concerned resources) to encrypt data at rest using an encryption key(s). The built-in/predefined IAM role Cloud KMS CryptoKey Decrypter allows the user/identity (with adequate privileges on concerned resources) to decrypt data at rest using an encryption key(s).
  
  Separation of duties is the concept of ensuring that one individual does not have all necessary permissions to be able to complete a malicious action. In Cloud KMS, this could be an action such as using a key to access and decrypt data a user should not normally have access to. Separation of duties is a business control typically used in larger organizations, meant to help avoid security or privacy incidents and errors. It is considered best practice.
  
  No user(s) should have Cloud KMS Admin and any of the Cloud KMS CryptoKey Encrypter/Decrypter, Cloud KMS CryptoKey Encrypter, Cloud KMS CryptoKey Decrypter roles assigned at the same time`,

  remediation: `**From Console:**
  
  1. Go to IAM & Admin/IAM using https://console.cloud.google.com/iam-admin/iam
  
  2. For any member having Cloud KMS Admin and any of the Cloud KMS CryptoKey Encrypter/Decrypter, Cloud KMS CryptoKey Encrypter, Cloud KMS CryptoKey Decrypter roles granted assigned, click the Delete Bin icon to remove the role from the member.`,

  references: ['https://cloud.google.com/kms/docs/separation-of-duties'],
  gql: `{
    querygcpIamPolicy { 
      id 
      __typename
      bindings {
        role
        members
      }
    }
  }`,
  resource: 'querygcpIamPolicy[*]',
  severity: 'medium',
  check: ({ resource }: any): boolean => {
    const memberInvalidRoles: string[] = []
    const memberRoles: { [member: string]: string[] } = {}

    resource.bindings?.forEach((binding: any) =>
      binding.members?.forEach((member: any) => {
        if (member.startsWith('user:')) {
          if (!memberRoles[member]) memberRoles[member] = [binding.role]
          else memberRoles[member].push(binding.role)
        }
      })
    )

    Object.entries(memberRoles).forEach(([key, value]) => {
      if (
        value.includes('roles/cloudkms.admin') &&
        (value.includes('roles/cloudkms.cryptoKeyEncrypterDecrypter') ||
          value.includes('roles/cloudkms.cryptoKeyEncrypter') ||
          value.includes('roles/cloudkms.cryptoKeyDecrypter'))
      )
        memberInvalidRoles.push(key)
    })

    return memberInvalidRoles.length === 0
  },
}
