export default {
  id: 'aws-nist-800-53-rev4-3.4',
  title: 'AWS NIST 3.4 EBS volume encryption should be enabled',

  description:
    'Enabling encryption on EBS volumes protects data at rest inside the volume, data in transit between the volume and the instance, snapshots created from the volume, and volumes created from those snapshots. By default, EBS volumes are encrypted with AWS managed KMS keys. Alternatively, you can specify a symmetric customer managed key as the default KMS key for EBS encryption via the AWS console and CLI.',

  audit: '',

  rationale: '',

  remediation: `**AWS Console**
        
  To create a new, encrypted EBS volume:

  - Navigate to EC2.
  - Select the Region in which you would like to create your volume.
  - In the navigation pane, select ELASTIC BLOCK STORE, Volumes.
  - Select Create Volume.
  - Select the desired values for Volume Type, Size, IOPS, Throughput, and Availability Zone.
  - To encrypt the volume, select Encrypt this volume, and choose a CMK.
  - Click Create Volume.

  **AWS CLI**

  Get a list of an instance’s volumes to see which are encrypted and unencrypted. Note the volume id and mount device for each unencrypted volume:

          aws ec2 describe-volumes --filters Name=attachment.instance-id, Values=<instance_id>

  Create a snapshot of an unencrypted EBS volume and track the snapshot id that is returned:

          aws ec2 create-snapshot --volume-id <unencrypted_volume_id>

  Make an encrypted copy of the snapshot you just created and get the new snapshot id:

          aws ec2 copy-snapshot --region <destination_region> --source-region <region> --encrypted --source-snapshot-id <snapshot_id>

  Create a new EBS volume from the encrypted snapshot and get the new volume id:

          aws ec2 create-volume --region <region> --availability-zone <availability_zone> --snapshot-id <snapshot_id> --volume-type gp2 --encrypted

  Stop the instance with the unencrypted EBS volume:

          aws ec2 stop-instance --instance-id <instance_id>

  Detatch the non-encrypted EBS volume:

          aws ec2 detach-volume --volume-id <unencrypted_volume_id>

  Attach the new encrypted EBS volume to the EC2 instance:

          aws ec2 attach-volume --volume-id <encrypted_volume_id> --instance-id <instance_id> --device <device>

  Restart the instance:

          aws ec2 start-instance --instance-id <instance_id>`,

  references: [
    'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html',
    'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-creating-volume.html',
    'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html',
    'https://docs.aws.amazon.com/cli/latest/reference/ec2/create-volume.html',
  ],
  gql: `{
    queryawsEbs {
      id
      arn
      accountId
      __typename
      encrypted
    }
  }`,
  resource: 'queryawsEbs[*]',
  severity: 'high',
  conditions: {
    path: '@.encrypted',
    equal: true,
  },
}
