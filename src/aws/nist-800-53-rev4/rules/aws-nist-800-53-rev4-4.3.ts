export default {
  id: 'aws-nist-800-53-rev4-4.3',  
  title: 'AWS NIST 4.3 ElastiCache transport encryption should be enabled',
  
  description: 'In-transit encryption should be enabled for ElastiCache replication groups. Encryption protects data from unauthorized access when it is moved from one location to another, such as from a primary node to a read replica mode in a replication group or between a replication group and application.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to [ElastiCache](https://console.aws.amazon.com/elasticache/).
  - In the left navigation, select Redis.
  - Create a [manual backup of the replication group](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-manual.html).
  - Create a new replication group by restoring from the backup setting the engine version to 3.2.6, 4.0.10 and later, and the parameter TransitEncryptionEnabled to true. Refer to [Restoring From a Backup with Optional Cluster Resizing](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-restoring.html) for more information.
  - Update the endpoints in your application to the new replication group’s endpoints. Refer to [Finding Connection Endpoints](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-restoring.html) for more information.
  - Delete the old replication group.
  
  **AWS CLI**
  
  Prerequisites:
  
      --engine Must be redis.
  
      --engine-version Must be 3.2.6, 4.0.10 or later.
  
  Encryption settings cannot be modified once created. Create a new replication group with transit encryption enabled to be used from scratch or seed the new group with a backup from an existing group.
  
  Create a backup of an existing cluster (if applicable). Note you will use replication-group-id or cache-cluster-id depending on your setup. You may skip this step if your existing cluster has automatic backups enabled. Locate the latest backup’s name to use for seeding your new cluster.
  
      aws elasticache create-snapshot --snapshot-name <snapshot-name> --replication-group-id <existing-replication-group-id>
  
  Create a new replication group, specifying the snapshot name if you created a backup in the first step. Note we are also creating two replicas and enabling automatic failover. Adjust these settings backed on your setup and requirements.
  
      aws elasticache create-replication-group --replication-group-id <new-replication-group-id> --replication-group-description <description> --engine redis --engine-version <minimum-3.2.6-or-4.0.10> --cache-node-type <node-instance-type> --transit-encryption-enabled --snapshot-name <snapshot-name> --replicas-per-node-group <replicas> --automatic-failover-enabled`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html',
      'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-manual.html',
      'https://docs.aws.amazon.com/cli/latest/reference/elasticache/create-snapshot.html',
      'https://docs.aws.amazon.com/cli/latest/reference/elasticache/create-replication-group.html',
  ],
  gql: `{
    queryawsElastiCacheCluster {
      id
      arn
      accountId
      __typename
      transitEncryptionEnabled
    }
  }`,
  resource: 'queryawsElastiCacheCluster[*]',
  severity: 'medium',
  conditions: { 
    path: '@.transitEncryptionEnabled',
    equal: true
  },
}
