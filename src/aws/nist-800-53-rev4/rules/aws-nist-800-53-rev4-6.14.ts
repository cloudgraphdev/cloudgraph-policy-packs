// AWS CIS 1.2.0 Rule equivalent 2.9
export default {
  id: 'aws-nist-800-53-rev4-6.14',  
  title: 'AWS NIST 6.14 VPC flow logging should be enabled',

  description: `VPC Flow Logs is a feature that enables you to capture information about the IP traffic
  going to and from network interfaces in your VPC. After you've created a flow log, you can
  view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow
  Logs be enabled for packet "Rejects" for VPCs.`,
  audit: `Perform the following to determine if VPC Flow logs is enabled:
  Via the Management Console:

  1. Sign into the management console
  2. Select *Services* then *VPC*
  3. In the left navigation pane, select *Your VPCs*
  4. Select a VPC
  5. In the right pane, select the *Flow Logs* tab.
  6. Ensure a Log Flow exists that has *Active* in the *Status* column.`,

  rationale: 'VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic or insight during security workflows.',

  remediation: `Perform the following to determine if VPC Flow logs is enabled:
  Via the Management Console:

  1. Sign into the management console
  2. Select *Services* then *VPC*
  3. In the left navigation pane, select *Your VPCs*
  4. Select a VPC
  5. In the right pane, select the *Flow Logs* tab.
  6. If no Flow Log exists, click *Create Flow Log*
  7. For Filter, select *Reject*
  8. Enter in a *Role* and *Destination Log Group*
  9. Click *Create Log Flow*
  10. Click on *CloudWatch Logs Group*

  **Note:** Setting the filter to "Reject" will dramatically reduce the logging data accumulation for this recommendation and provide sufficient information for the purposes of breach detection, research, and remediation. However, during periods of least privilege security group engineering, setting this filter to "All" can be very helpful in discovering existing traffic flows required for the proper operation of an already running environment.`,

  references: [
    'https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-cwl.html',
    'https://docs.aws.amazon.com/cli/latest/reference/ec2/create-flow-logs.html',
  ],
  gql: `{
    queryawsVpc {
      id
      arn
      accountId
       __typename
      flowLog {
        logStatus
      }
    }
  }`,
  resource: 'queryawsVpc[*]',
  severity: 'medium',
  conditions: {
    path: '@.flowLog',
    array_any: {
      path: '[*].logStatus',
      equal: 'ACTIVE'
    }
  },
}
