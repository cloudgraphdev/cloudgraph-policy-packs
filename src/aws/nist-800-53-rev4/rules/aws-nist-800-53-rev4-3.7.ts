export default {
  id: 'aws-nist-800-53-rev4-3.7',
  title:
    'AWS NIST 3.7 SQS queue server-side encryption should be enabled with KMS keys',

  description:
    'When using SQS queues to send and receive sensitive data, message payloads should be encrypted using server-side encryption with keys managed in KMS (SSE-KMS). Using SQS owned keys (SSE-SQS) is also an option, but lacks the benefits of using KMS, including viewing key policies, auditing usage, and rotating cryptographic material',

  audit: '',

  rationale: '',

  remediation: `**AWS Console**

  - Navigate to SQS.
  - Select an existing queue.
  - From Queue Actions, select Configure Queue.
  - Under Server-Side Encryption (SSE) Settings, check Use SSE.
  - Next to AWS KMS Customer Master Key (CMK), select a key.
  - Select Save Changes

  **AWS CLI**

  Encrypt SQS Queue using a KMS key:

          aws sqs set-queue-attributes --queue-url <url> --attributes '{"KmsMasterKeyId":"<key-id>","KmsDataKeyReusePeriodSeconds":"60"}'`,

  references: [
    'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html',
    'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-sse-existing-queue.html',
    'https://docs.aws.amazon.com/cli/latest/reference/sqs/set-queue-attributes.html',
  ],
  gql: `{
    queryawsSqs {
      id
      arn
      accountId
      __typename
      kmsMasterKeyId
    }
  }`,
  resource: 'queryawsSqs[*]',
  severity: 'high',
  conditions: {
    path: '@.kmsMasterKeyId',
    isEmpty: false,
  },
}
