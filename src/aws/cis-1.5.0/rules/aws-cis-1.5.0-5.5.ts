export default {
  id: 'aws-cis-1.5.0-5.4',
  title:
    'AWS CIS 5.4 Ensure routing tables for VPC peering are "least access"',

  description:
    'Once a VPC peering connection is established, routing tables must be updated to establish any connections between the peered VPCs. These routes can be as specific as desired - even peering a VPC to only a single host on the other side of the connection.',

  audit: `Review routing tables of peered VPCs for whether they route all subnets of each VPC and whether that is necessary to accomplish the intended purposes for peering the VPCs.

**From Command Line:**

1. List all the route tables from a VPC and check if "GatewayId" is pointing to a <peering_connection_id> (e.g. pcx-1a2b3c4d) and if "DestinationCidrBlock" is as specific as desired.

        aws ec2 describe-route-tables --filter "Name=vpc-id,Values=<vpc_id>" --query "RouteTables[*].{RouteTableId:RouteTableId, VpcId:VpcId, Routes:Routes, AssociatedSubnets:Associations[*].SubnetId}"`,

  rationale:
    'Being highly selective in peering routing tables is a very effective way of minimizing the impact of breach as resources outside of these routes are inaccessible to the peered VPC.',

  remediation: `Remove and add route table entries to ensure that the least number of subnets or hosts as is required to accomplish the purpose for peering are routable. 

**From Command Line:**

1. For each <route_table_id> containing routes non compliant with your routing policy (which grants more than desired "least access"), delete the non compliant route: 

        aws ec2 delete-route --route-table-id <route_table_id> --destination-cidr-block <non_compliant_destination_CIDR>

2. Create a new compliant route:

        aws ec2 create-route --route-table-id <route_table_id> --destination-cidr-block <compliant_destination_CIDR> --vpc-peering-connection-id <peering_connection_id>`,

  references: [
    'https://docs.aws.amazon.com/AmazonVPC/latest/PeeringGuide/peering-configurations-partial-access.html',
    'https://docs.aws.amazon.com/cli/latest/reference/ec2/create-vpc-peering-connection.html',
  ],

  severity: 'high',
}
