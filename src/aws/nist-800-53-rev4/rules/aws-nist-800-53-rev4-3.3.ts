export default {
  id: 'aws-nist-800-53-rev4-3.3',  
  title: 'AWS NIST 3.3 DynamoDB tables should be encrypted with AWS or customer managed KMS keys',
  
  description: 'Although DynamoDB tables are encrypted at rest by default with AWS owned KMS keys, using AWS managed or customer managed KMS keys provides additional functionality, such as viewing key policies, auditing usage, and rotating cryptographic material.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to DynamoDB.
  - In the navigation pane, choose Tables.
  - Select your table.
  - On the Overview tab, locate Encryption Type under Table details.
  - Click Manage Encryption.
  - Select KMS.
  - Click Save
  
  **AWS CLI**
  
  KMS encryption can be enabled at table creation and on an existing table.
  
  Create a KMS encrypted DynamoDB table:
  
          aws dynamodb create-table --table-name <table-name> --attribute-definitions <attribute-names> --key-schema <attribute-names> --provisioned-throughput <throughput-parameters> --sse-specification Enabled=true,SSEType=KMS
  
  Update an existing table with KMS encryption:
  
          aws dynamodb update-table --table-name <table-name> --sse-specification Enabled=true,SSEType=KMS`,
  
  references: [
          'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html',
          'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/encryption.tutorial.html',
          'https://docs.aws.amazon.com/cli/latest/reference/dynamodb/create-table.html#examples',
          'https://docs.aws.amazon.com/cli/latest/reference/dynamodb/update-table.html',
  ],   
  gql: `{
    queryawsDynamoDbTable {
      id
      arn
      accountId
       __typename
      sseDescription {
        status
        sseType
      }
    }
  }`,
  resource: 'queryawsDynamoDbTable[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.sseDescription.status',
        equal: 'ENABLED',
      },
      {
        path: '@.sseDescription.sseType',
        equal: 'KMS',
      },
    ],
  },
}
