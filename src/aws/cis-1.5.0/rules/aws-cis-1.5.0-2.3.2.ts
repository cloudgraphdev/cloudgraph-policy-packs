export default {
id: 'aws-cis-1.5.0-2.3.2',  
  title: 'AWS CIS 2.3.2 Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances',
  
  description: 'Ensure that RDS database instances have the Auto Minor Version Upgrade flag enabled in order to receive automatically minor engine upgrades during the specified maintenance window. So, RDS instances can get the new features, bug fixes, and security patches for their database engines.',
  
  audit: `**From Console:**

  1. Log in to the AWS management console and navigate to the RDS dashboard at https://console.aws.amazon.com/rds/.
  2. In the left navigation panel, click on Databases.
  3. Select the RDS instance that wants to examine.
  4. Click on the Maintenance and backups panel.
  5. Under the Maintenance section, search for the Auto Minor Version Upgrade status.

  • If the current status is set to Disabled, means the feature is not set and the minor engine upgrades released will not be applied to the selected RDS instance
  
  **From Command Line:**

  1. Run *describe-db-instances* command to list all RDS database names, available in the selected AWS region:

          aws rds describe-db-instances --region <regionName> --query 'DBInstances[*].DBInstanceIdentifier'
  
  2. The command output should return each database instance identifier.
  3. Run again *describe-db-instances* command using the RDS instance identifier returned earlier to determine the Auto Minor Version Upgrade status for the selected instance:

          aws rds describe-db-instances --region <regionName> --db-instance-identifier <dbInstanceIdentifier> --query 'DBInstances[*].AutoMinorVersionUpgrade'

  4. The command output should return the feature current status. If the current status is set to true, the feature is enabled and the minor engine upgrades will be applied to the selected RDS instance.`,
  
  rationale: 'AWS RDS will occasionally deprecate minor engine versions and provide new ones for an upgrade. When the last version number within the release is replaced, the version changed is considered minor. With Auto Minor Version Upgrade feature enabled, the version upgrades will occur automatically during the specified maintenance window so your RDS instances can get the new features, bug fixes, and security patches for their database engines.',
  
  remediation: `**From Console:**

  1. Log in to the AWS management console and navigate to the RDS dashboard at https://console.aws.amazon.com/rds/.
  2. In the left navigation panel, click on Databases.
  3. Select the RDS instance that wants to update.
  4. Click on the *Modify* button placed on the top right side.
  5. On the *Modify DB Instance: <instance identifier>* page, In the *Maintenance* section, select *Auto minor version upgrade* click on the *Yes* radio button.
  6. At the bottom of the page click on *Continue*, check to Apply Immediately to apply the changes immediately, or select *Apply during the next scheduled maintenance window* to avoid any downtime.
  7. Review the changes and click on *Modify DB Instance*. The instance status should change from available to modifying and back to available. Once the feature is enabled, the *Auto Minor Version Upgrade* status should change to *Yes*.
  
  **From Command Line:**

  1. Run *describe-db-instances* command to list all RDS database instance names, available in the selected AWS region:

          aws rds describe-db-instances --region <regionName> --query 'DBInstances[*].DBInstanceIdentifier'
  2. The command output should return each database instance identifier.
  3. Run the *modify-db-instance* command to modify the selected RDS instance configuration this command will apply the changes immediately, Remove -- *apply-immediately* to apply changes during the next scheduled maintenance window and avoid any downtime:
  
          aws rds modify-db-instance --region <regionName> --db-instance-identifier <dbInstanceIdentifier> --auto-minor-version-upgrade --apply-immediately

  4. The command output should reveal the new configuration metadata for the RDS instance and check *AutoMinorVersionUpgrade* parameter value.
  5. Run *describe-db-instances* command to check if the Auto Minor Version Upgrade feature has been successfully enable:

          aws rds describe-db-instances --region <regionName> --db-instance-identifier <dbInstanceIdentifier> --query 'DBInstances[*].AutoMinorVersionUpgrade'

  6. The command output should return the feature current status set to *true*, the feature is *enabled* and the minor engine upgrades will be applied to the selected RDS instance.`,
  
  references: [
    'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_RDS_Managing.html',
    'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Upgrading.html',
    'https://aws.amazon.com/rds/faqs/',
  ],
  gql: `{
    queryawsRdsDbInstance {
      id
      arn
      accountId
      __typename
      autoMinorVersionUpgrade
    }
  }`,
  resource: 'queryawsRdsDbInstance[*]',
  severity: 'high',
  conditions: {
    path: '@.autoMinorVersionUpgrade',
    equal: true,
  },
}