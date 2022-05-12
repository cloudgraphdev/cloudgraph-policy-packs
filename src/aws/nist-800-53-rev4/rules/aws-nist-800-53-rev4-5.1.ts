export default {
  id: 'aws-nist-800-53-rev4-5.1',
  title:
    'AWS NIST 5.1 RDS instances should have FedRAMP approved database engines',

  description:
    'FedRAMP-approved database engines such as MySQL and PostgresQL satisfy strict U.S. government requirements for securing sensitive data. An RDS instance should use an approved database engine.',

  audit: '',

  rationale: '',

  remediation: `**AWS Console**
  
  - You cannot modify an existing database. You need to migrate to a new database instance that is FedRAMP approved. Here is a list of services that are FedRAMP Approved.
  
  - Backup and restore your database instance. Make sure you select a database engine that is FedRAMP approved, such as MySQL.
  
  **AWS CLI**
  
  - These steps use a database instance. If you wish to use a database cluster, the API calls are similarly named *create-db-cluster-snapshot*, *modify-db-cluster*, and *restore-db-cluster-from-snapshot*.
  
  - Create a backup of your existing RDS database or skip this step if you already have a snapshot.
  
          aws rds create-db-snapshot --db-instance-identifier <db-id> --db-snapshot-identifier <snapshot-id>
  
  - Rename your database instance if you wish to use the same identifier for your new database instance. Note this will take effect during your next maintenance window which will cause your instance to reboot. You can also use the *apply-immediately* parameter.
  
          aws rds modify-db-instance --db-instance-identifier <db-id> --new-db-instance-identifier <new-db-id>
  
  - Restore your snapshot to a new database instance using a FedRAMP approved database engine.
  
          aws rds restore-db-instance-from-db-snapshot --db-instance-identifier <db-id> --db-snapshot-identifier <snapshot-id> --db-instance-class <class> --engine <engine>`,

  references: [
    'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_CommonTasks.BackupRestore.html',
    'https://aws.amazon.com/compliance/services-in-scope/',
    'https://docs.aws.amazon.com/cli/latest/reference/rds/create-db-snapshot.html',
    'https://docs.aws.amazon.com/cli/latest/reference/rds/modify-db-instance.html',
    'https://docs.aws.amazon.com/cli/latest/reference/rds/restore-db-instance-from-db-snapshot.html',
  ],
  gql: `{
    queryawsRdsDbInstance {
      id
      arn
      accountId
      __typename
      engine
    }
  }`,
  resource: 'queryawsRdsDbInstance[*]',
  severity: 'low',
  conditions: {
    path: '@.engine',
    in: [
      'aurora',
      'aurora-mysql',
      'aurora-postgresql',
      'mariadb',
      'mysql',
      'oracle-ee',
      'oracle-ee-cdb',
      'oracle-se2',
      'oracle-se2-cdb',
      'postgres',
      'sqlserver-ee',
      'sqlserver-se',
      'sqlserver-ex',
      'sqlserver-web',
    ],
  },
}
