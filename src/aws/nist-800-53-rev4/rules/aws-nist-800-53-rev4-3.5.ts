export default {
  id: 'aws-nist-800-53-rev4-3.5',
  title: 'AWS NIST 3.5 RDS instances should be encrypted',
  
  description:
  'Encrypting your RDS DB instances provides an extra layer of security by securing your data from unauthorized access. You have the option of using an AWS managed or customer managed KMS key for this purpose.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - You cannot modify an existing database to enable encryption. You need to migrate to a new RDS instance. Navigate to RDS.
  - In the left navigation, select Snapshots.
  - Create a database snapshot.
  - Make a copy of the snapshot and make sure to enable encryption.
  
  **AWS CLI**
  
  List all RDS instances:
  
          aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier'
  
  Check if each RDS instance is encrypted:
  
          aws rds describe-db-instances --db-instance-identifier <instance name> --query 'DBInstances[*].StorageEncrypted'
  
  If an instance shows “false”, create a snapshot of it:
  
          aws rds create-db-snapshot --db-instance-identifier <instance name> --db-snapshot-identifier <name of new snapshot>
  
  Make an encrypted copy of the snapshot:
  
          aws rds copy-db-snapshot --source-db-snapshot-identifier <instance name> --target-db-snapshot-identifier <new name of second snapshot> --kms-key-id <arn of RDS master key>
  
  Restore snapshot to new database instance:
  
          aws rds restore-db-instance-from-db-snapshot --db-instance-identifier <new db instance name> --db-snapshot-identifier <name of second snapshot>
  
  Point your application to the new database instance.`,
  
  references: [
  'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
  'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_CommonTasks.BackupRestore.html',
  'https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-instances.html',
  'https://docs.aws.amazon.com/cli/latest/reference/rds/create-db-snapshot.html',
  'https://docs.aws.amazon.com/cli/latest/reference/rds/copy-db-snapshot.html',
  'https://docs.aws.amazon.com/cli/latest/reference/rds/restore-db-instance-from-db-snapshot.html',
  ],
  gql: `{
   queryawsRdsDbInstance {
      id
      arn
      accountId
      __typename
      encrypted
    }
  }`,
  resource: 'queryawsRdsDbInstance[*]',
  severity: 'high',
  conditions: {
    path: '@.encrypted',
    equal: true,
  },
}
