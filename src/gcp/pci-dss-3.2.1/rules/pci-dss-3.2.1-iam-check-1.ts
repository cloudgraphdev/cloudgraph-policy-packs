// GCP CIS 1.2.0 Rule equivalent 1.11
export default {
  id: 'gcp-pci-dss-3.2.1-iam-check-1',  
  title: 'IAM check 1: IAM users should not have both KMS admin and any of the KMS encrypter/decrypter roles',  
  
  description: 'It is recommended that the principle of "Separation of Duties" is enforced while assigning KMS related roles to users.',  

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
  severity: 'unknown',
  conditions: {
    jq: `[({"member" : .bindings[].members[], "roles" : .bindings[].role}) ]  
    | group_by(.member) 
    | map({ "member" : .[].member, "roles" : map(.roles) }) 
    | [.[] 
    | select(.roles 
    | contains(["roles/cloudkms.admin", "roles/cloudkms.cryptoKeyEncrypterDecrypter"]) 
      or contains(["roles/cloudkms.admin", "roles/cloudkms.cryptoKeyEncrypter"]) 
      or contains(["roles/cloudkms.admin", "roles/cloudkms.cryptoKeyDecrypter"]))] 
    | {"userHasInvalidRoles":  ( (. | length) > 0)}`,
    path: '@',
    and: [
      {
        path: '@.userHasInvalidRoles',
        notEqual: true,
      },
    ],
  },
}