export default {
  id: 'aws-cis-1.2.0-2.9',
  description:
    'AWS CIS 2.9 Ensure VPC flow logging is enabled in all VPCs (Scored)',
  audit: `Perform the following to determine if VPC Flow logs is enabled:  
  Via the Management Console:
  
  1. Sign into the management console
  2. Select *Services* then *VPC*
  3. In the left navigation pane, select *Your VPCs*
  4. Select a VPC
  5. In the right pane, select the *Flow Logs* tab.
  6. Ensure a Log Flow exists that has *Active* in the *Status* column.`,
  rationale: `VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic or insight during security workflows.`,
  remediation:  `Perform the following to determine if VPC Flow logs is enabled:
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
    `CCE- 79202 - 8`,
    `CIS CSC v6.0 #6.5, #12.9`,
    `http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html`,
  ],
  gql: `{
    queryawsVpc {
      id
      __typename
      flowLogs {
        resourceId
      }
    }
  }`,
  resource: 'queryawsVpc[*]',
  severity: 'medium',
  conditions: {
    path: '@.flowLogs',
    isEmpty: false,
  },
}
