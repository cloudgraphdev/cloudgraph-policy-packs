export default {
  id: 'aws-pci-dss-3.2.1-ssm-check-1',
  title:
    'SSM Check 1: Amazon EC2 instances managed by Systems Manager should have a patch compliance status of COMPLIANT after a patch installation',
  description: `This control checks whether the compliance status of the Amazon EC2 Systems Manager patch compliance is COMPLIANT or NON_COMPLIANT after the patch installation on the instance.

  It only checks instances that are managed by AWS Systems Manager Patch Manager.
  
  It does not check whether the patch was applied within the 30-day limit prescribed by PCI DSS requirement 6.2.
  
  It also does not validate whether the patches applied were classified as security patches.
  
  You should create patching groups with the appropriate baseline settings and ensure in-scope systems are managed by those patch groups in Systems Manager. For more information about patch groups, see the [AWS Systems Manager User Guide](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-patch-group-tagging.html).
  
  **Note**
  This control is not supported in the following Regions.

  * Africa (Cape Town)

  * Asia Pacific (Osaka)

  * Europe (Milan)`,
  rationale: `**PCI DSS 6.2: Ensure that all system components and software are protected from known vulnerabilities by installing applicable vendor-supplied security patches. Install critical security patches within one month of release.**
  
  Patches released by the vendor for systems that are in-scope for PCI DSS should be tested and validated before installation in production environment. Once deployed, security settings and controls should be validated to ensure that deployed patches have not impacted the security of the cardholder data environment (CDE).

If you use Amazon EC2 instances managed by AWS Systems Manager Patch Manager to patch managed instances in your CDE, ensure that the patches are successfully applied. To do this, check that the compliance status of the Amazon EC2 Systems Manager patch compliance is "COMPLIANT". Patch Manager can apply both operating systems and applications applicable patches.

This is a method used to protect system components and software from known vulnerabilities.`,
  remediation: `
  **To remediate noncompliant patches**

  This rule checks whether the compliance status of the Amazon EC2 Systems Manager patch compliance is COMPLIANT or NON_COMPLIANT. To find out more about patch compliance states, see the [AWS Systems Manager User Guide](https://docs.aws.amazon.com/systems-manager/latest/userguide/about-patch-compliance-states.html).
  
  1. Open the AWS Systems Manager console at https://console.aws.amazon.com/systems-manager/.
  
  2. In the navigation pane, under **Node Management**, choose **Run Command**.
  
  3. Choose **Run command**.
  
  4. Choose the radio button next to AWS-RunPatchBaseline and then change the **Operation** to **Install**.
  
  5. Choose **Choose instances manually** and then choose the noncompliant instance(s).
  
  6. Scroll to the bottom and then choose **Run**.
  
  7. After the command has completed, to monitor the new compliance status of your patched instances, in the navigation pane, choose **Compliance**.
  
  See the AWS Systems Manager User Guide for more information about the following
  * [Using Systems Manager documents to patch a managed instance](https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager-ssm-documents.html)
  * [Running commands using the Systems Manager Run command](https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html)`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-ssm-1',
    'https://d1.awsstatic.com/whitepapers/compliance/pci-dss-compliance-on-aws.pdf'
  ],
  gql: `{
    queryawsSystemsManagerInstance {
      id
      arn
      accountId
      __typename
      complianceItems {
        complianceType
        status
      }
    }
  }`,
  resource: 'queryawsSystemsManagerInstance[*]',
  severity: 'medium',
  conditions: {
    not: {
      path: '@.complianceItems',
      array_any: {
        and: [
          {
            path: '[*].complianceType',
            equal: 'Patch'
          },
          {
            path: '[*].status',
            notEqual: 'COMPLIANT'
          }
        ]
      }
    }
  },
}
