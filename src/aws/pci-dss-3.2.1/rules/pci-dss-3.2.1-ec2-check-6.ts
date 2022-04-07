export default {
  id: 'aws-pci-dss-3.2.1-ec2-check-6',
  title: 'EC2 Check 6: VPC flow logging should be enabled in all VPCs',
  description: `This control checks whether VPC flow logs are found and enabled for VPCs. The traffic type is set to REJECT.

  With VPC Flow Logs, you can capture information about the IP address traffic to and from network interfaces in your VPC. After you create a flow log, you can use CloudWatch Logs to view and retrieve the log data.

  Security Hub recommends that you enable flow logging for packet rejects for VPCs. Flow logs provide visibility into network traffic that traverses the VPC. They can detect anomalous traffic and provide insight into security workflows.

  By default, the record includes values for the different components of the IP address flow, including the source, destination, and protocol. For more information and descriptions of the log fields, see [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html) in the Amazon VPC User Guide.`,
  rationale: `**PCI DSS 10.3.3 Verify date and time stamp is included in log entries.**
  By enabling VPC flow logging for your VPC, you can identify the date and time of a log entry. The event date and time are recorded in the start and end fields. The values are displayed in Unix seconds.

  **PCI DSS 10.3.4 Verify success or failure indication is included in log entries.**
  By enabling VPC flow logging for your VPC, you can identify the type of event that occurred. The type of event is recorded in the action field, and can be either ACCEPT or REJECT.

  **PCI DSS 10.3.5 Verify origination of event is included in log entries.**
  By enabling VPC flow logging for your VPC, you can verify the origin of an event. The event origin is recorded in the pkt-srcaddr, srcaddr, and srcport fields. These fields show the source IP address and source port of the traffic.

  **PCI DSS 10.3.6 Verify identity or name of affected data, system component, or resources is included in log entries.**
  By enabling VPC flow logging for your VPC, you can verify the identity or name of affected data, system components, or resources. The pkt-dstaddr, dstaddr, and dstport fields show the destination IP address and destination port of the traffic.`,
  remediation: `**To enable VPC flow logging**

  1. Open the Amazon VPC console at https://console.aws.amazon.com/vpc/.

  2. In the navigation pane, under **Virtual Private Cloud**, choose **Your VPCs**.

  3. Select a VPC to update.

  4. At the bottom of the page, choose **Flow Logs**.

  5. Choose **Create flow log**.

  6. For **Filter**, choose **Reject**.

  7. For **Destination log group**, choose the log group to use.

  8. If you chose **CloudWatch Logs** for your destination log group, for IAM role, choose the **IAM role** to use.

  9. Choose **Create**.
  `,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html',
  ],
  gql: `{
    queryawsVpc {
      id
      arn
      accountId
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
