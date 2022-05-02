export default {
  id: 'aws-nist-800-53-rev4-2.5',  
  title: 'AWS NIST 2.5 S3 bucket replication (cross-region or same-region) should be enabled',
  
  description: 'Cross-Region S3 replication can help with meeting compliance requirements, minimizing latency, and increasing operational efficiency. Same-Region S3 replication can help with aggregating logs and compliance with data sovereignty laws.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**AWS Console**
  
  - Navigate to S3.
  - Select the S3 bucket.
  - Choose Management > Replication > Add rule.
  - In Set source, select the Entire bucket.
  - Click Next.
  - In Set destination, select to create a new bucket.
  - Enter the bucket name.
  - Select the either the same-region or a cross-region.
  - Click Next.
  - From the IAM role drop-down, select Create new role.
  - Enter a name for the role.
  - In Status, select Enabled.
  - Click Next.
  - Review your configuration settings and click Save.
  
  **AWS CLI**
  
  To enable replication for your S3 bucket:
  
      Create a source bucket and enable versioning on it.
  
      aws s3api create-bucket \
      --bucket source \
      --region us-east-1 \
      --profile acctA
  
      aws s3api put-bucket-versioning \
      --bucket source \
      --versioning-configuration Status=Enabled \
      --profile acctA
  
  Create the destination bucket and enable versioning on it.
  
      aws s3api create-bucket \
      --bucket destination \
      --region us-west-2 \
      --create-bucket-configuration LocationConstraint=us-west-2 \
      --profile acctA
  
      aws s3api put-bucket-versioning \
      --bucket destination \
      --versioning-configuration Status=Enabled \
      --profile acctA
  
  Create an IAM role that will be added to the source bucket in a later step.
  
      {
          "Version": "2012-10-17",
          "Statement": [
              {
                  "Effect": "Allow",
                  "Principal": {
                      "Service": "s3.amazonaws.com"
                  },
                  "Action": "sts:AssumeRole"
              }
          ]
      }
  
  Run the following command to create the role.
  
      aws iam create-role \
      --role-name replicationRole \
      --assume-role-policy-document file://s3-role-trust-policy.json  \
      --profile acctA
  
  Attach a permission policy to the role.
  
      {
           "Version": "2012-10-17",
           "Statement": [
              {
                 "Effect": "Allow",
                 "Action": [
                    "s3:GetObjectVersionForReplication",
                    "s3:GetObjectVersionAcl"
                 ],
                 "Resource": [
                    "arn:aws:s3:::source-bucket/*"
                 ]
              },
              {
                 "Effect": "Allow",
                 "Action": [
                    "s3:ListBucket",
                    "s3:GetReplicationConfiguration"
                 ],
                 "Resource": [
                    "arn:aws:s3:::source-bucket"
                 ]
              },
              {
                 "Effect": "Allow",
                 "Action": [
                    "s3:ReplicateObject",
                    "s3:ReplicateDelete",
                    "s3:ReplicateTags",
                    "s3:GetObjectVersionTagging"
  
                 ],
                 "Resource": [
                    "arn:aws:s3:::destination-bucket/*"
                 ]
              }
           ]
        }
  
  Create the policy and attach it to the role.
  
      aws iam put-role-policy \
      --role-name replicationRole \
      --policy-document file://s3-role-permissions-policy.json \
      --policy-name replicationRolePolicy \
      --profile acctA
  
  Add the replication configuration to the source bucket.
  
      {
          "Role": "IAM-role-ARN",
          "Rules": [
              {
              "Status": "Enabled",
              "Priority": 1,
              "DeleteMarkerReplication": { "Status": "Disabled" },
              "Filter" : { "Prefix": "Tax"},
              "Destination": {
                  "Bucket": "arn:aws:s3:::destination-bucket"
              }
              }
          ]
      }
  
  Update the JSON by providing values for the destination-bucket and IAM-role-ARN.
  
  Save the changes.
  
  Add the replication configuration to your source bucket.
  
      aws s3api put-bucket-replication \
      --replication-configuration file://replication.json \
      --bucket source \
      --profile acctA
  
  To retrieve the replication configuration:
  
      aws s3api get-bucket-replication \
      --bucket source \
      --profile acctA`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/enable-replication.html',
      'https://docs.aws.amazon.com/AmazonS3/latest/dev/setting-repl-config-perm-overview.html',
  ],
  gql: `{
    queryawsS3 {
      id
      arn
      accountId
      __typename
      crossRegionReplication
    }
  }`,
  resource: 'queryawsS3[*]',
  severity: 'medium',
  conditions: {
    path: '@.crossRegionReplication',
    equal: 'Enabled',
  },
}
