export default {
  id: 'aws-nist-800-53-rev4-2.3',  
  title: 'AWS NIST 2.3 RDS Aurora cluster multi-AZ should be enabled',
  
  description: 'An Aurora cluster in a Multi-AZ (availability zone) deployment provides enhanced availability and durability of data. When an Aurora cluster is provisioned, Amazon creates a primary DB instance and replicates the data to a Aurora replica in another availability zone.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  AWS does not allow you to change an Aurora cluster’s multi-AZ setting after deployment.
  
  To create a new Aurora cluster with multi-AZ enabled:
  
  - Navigate to [RDS](https://console.aws.amazon.com/rds/home).
  - Select Create Database.
  - Select Standard Create.
  - Select Amazon Aurora as the engine type.
  - Under Availability & durability, Multi-AZ deployment, select Create an Aurora Replica/Reader node in a different AZ.
  - Configure the rest of the settings as desired.
  - Select Create Database.
  
  **AWS CLI**
  
  AWS does not allow you to change an Aurora cluster’s multi-AZ setting after deployment.
  
  To create a new Aurora MySQL DB cluster with multi-AZ enabled:
  
  Create the Aurora MySQL DB cluster:
  
      aws rds create-db-cluster --db-cluster-identifier <db cluster identifier> --engine aurora-mysql \
          --engine-version 5.7.12 --master-username <username> --master-user-password <password> \
          --db-subnet-group-name <subnet group name> --vpc-security-group-ids <sg-ids>
  
  Create the primary instance for your MySQL DB cluster:
  
      aws rds create-db-instance --db-instance-identifier <db instance identifier> \
       --db-cluster-identifier <db cluster identifier> --engine aurora-mysql --db-instance-class <instance class>
  
  To create a new Aurora PostgreSQL DB cluster with multi-AZ enabled:
  
  Create the PostgreSQL DB cluster:
  
      aws rds create-db-cluster --db-cluster-identifier <db cluster identifier> --engine aurora-postgresql \
          --master-username <username> --master-user-password <password> \
          --db-subnet-group-name <subnet group name> --vpc-security-group-ids <sg-ids>
  
  Create the primary instance for your PostgreSQL DB cluster:
  
      aws rds create-db-instance --db-instance-identifier <db instance identifier> \
       --db-cluster-identifier <db cluster identifier> --engine aurora-postgresql --db-instance-class <instance class>`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Modifying.html#Aurora.Modifying.SettingsNotApplicable',
      'https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.CreateInstance.html#Aurora.CreateInstance.Creating',
      'https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.CreateInstance.html#Aurora.CreateInstance.Creating.CLI',
      'https://docs.aws.amazon.com/cli/latest/reference/rds/create-db-cluster.html',
      'https://docs.aws.amazon.com/cli/latest/reference/rds/create-db-instance.html',
  ],
  gql: `{
    queryawsAccount {
      id
      arn
      accountId
      __typename
      rdsClusters {
        engine
        multiAZ
      }
    }
  }`,
  resource: 'queryawsAccount[*]',
  severity: 'medium',
  conditions: {
    path: '@.rdsClusters',
    array_any: {    
      and: [
        {
          path: '[*].engine',
          match: /^aurora-.*$/,
        },
        {
          path: '[*].multiAZ',
          equal: true,
        },
      ],
    },
  },
}
