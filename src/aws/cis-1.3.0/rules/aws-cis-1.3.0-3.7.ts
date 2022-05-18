// AWS CIS 1.2.0 Rule equivalent 2.7
export default {
  id: 'aws-cis-1.3.0-3.7',
  title:
    'AWS CIS 3.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs',
  description: `AWS CloudTrail is a web service that records AWS API calls for an account and makes those
  logs available to users and resources in accordance with IAM policies. AWS Key
  Management Service (KMS) is a managed service that helps create and control the
  encryption keys used to encrypt account data, and uses Hardware Security Modules
  (HSMs) to protect the security of encryption keys. CloudTrail logs can be configured to
  leverage server side encryption (SSE) and KMS customer created master keys (CMK) to
  further protect CloudTrail logs. It is recommended that CloudTrail be configured to use
  SSE-KMS.`,
  audit: `Perform the following to determine if CloudTrail is configured to use SSE-KMS:
  Via the Management Console

  1. Sign in to the AWS Management Console and open the CloudTrail console at https://console.aws.amazon.com/cloudtrail
  2. In the left navigation pane, choose *Trails*.
  3. Select a Trail
  4. Under the *S3* section, ensure *Encrypt log files* is set to *Yes* and a KMS key ID is specified in the *KSM Key Id* field.

  Via CLI

  1. Run the following command:

    aws cloudtrail describe-trails

  2. For each trail listed, SSE-KMS is enabled if the trail has a *KmsKeyId* property defined.`,
  rationale: 'Configuring CloudTrail to use SSE-KMS provides additional confidentiality controls on log data as a given user must have S3 read permission on the corresponding log bucket and must be granted decrypt permission by the CMK policy.',
  remediation: `Perform the following to configure CloudTrail to use SSE-KMS:
  Via the Management Console

  1. Sign in to the AWS Management Console and open the CloudTrail console at https://console.aws.amazon.com/cloudtrail
  2. In the left navigation pane, choose *Trails*.
  3. Click on a Trail
  4. Under the *S3* section click on the edit button (pencil icon)
  5. Click *Advanced*
  6. Select an existing CMK from the *KMS key Id* drop-down menu

  - Note: Ensure the CMK is located in the same region as the S3 bucket
  - Note: You will need to apply a KMS Key policy on the selected CMK in order for CloudTrail as a service to encrypt and decrypt log files using the CMK provided. Steps are provided [here](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html) for editing the selected CMK Key policy.

  7. Click *Save*
  8. You will see a notification message stating that you need to have decrypt
      permissions on the specified KMS key to decrypt log files.
  9. Click *Yes*

  Via CLI

    aws cloudtrail update-trail --name <trail_name> --kms-id <cloudtrail_kms_key>
    aws kms put-key-policy --key-id <cloudtrail_kms_key> --policy <cloudtrail_kms_key_policy>`,
  references: [
    'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html',
    'https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html',
    'CCE-78919-8',
  ],
  gql: `{
    queryawsCloudtrail {
      id
      arn
      accountId
       __typename
			kmsKeyId
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'medium',
  conditions: {
    path: '@.kmsKeyId',
    notEqual: null,
  },
}
