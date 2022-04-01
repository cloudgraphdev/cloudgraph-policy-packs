export default {
  id: 'aws-nist-800-53-rev4-2.4',  
  title: 'AWS NIST 2.4 Require Multi Availability Zones turned on for RDS Instances',
  
  description: 'Multi availability zones must be enabled for RDS Instances.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to RDS.
  - In the left navigation, select Snapshots.
  - Create a database snapshot.
  - Select the snapshot and click Actions > Restore Snapshot.
  - On the Restore DB Instance page, ensure Multi-AZ deployment is enabled.
  - Select Restore DB Instance.
  
  **AWS CLI**
  
  List all RDS instances:
  
      aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier'
  
  Check if each RDS instance has Multi-AZ enabled:
  
      aws rds describe-db-instances --db-instance-identifier <instance name> --query 'DBInstances[*].MultiAZ'
  
  If an instance shows “false”, create a snapshot of it:
  
      aws rds create-db-snapshot --db-instance-identifier <instance name> --db-snapshot-identifier <name of new snapshot>
  
  Restore snapshot to new database instance with Multi-AZ enabled:
  
      aws rds restore-db-instance-from-db-snapshot --db-instance-identifier <new db instance name> --db-snapshot-identifier <name of second snapshot> --multi-az`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CreateSnapshot.html',
      'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_RestoreFromSnapshot.html',
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
      multiAZ
    }
  }`,
  resource: 'queryawsRdsDbInstance[*]',
  severity: 'medium',
  conditions: {
    path: '@.multiAZ',
    equal: true,
  },
}
