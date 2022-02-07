export default {
  id: 'gcp-cis-1.2.0-4.11',
  title:
    'GCP CIS 4.11 Ensure that Compute instances have Confidential Computing enabled',
  description: `Google Cloud encrypts data at-rest and in-transit, but customer data must be decrypted for
  processing. Confidential Computing is a breakthrough technology which encrypts data in-
  use—while it is being processed. Confidential Computing environments keep data
  encrypted in memory and elsewhere outside the central processing unit (CPU).

  Confidential VMs leverage the Secure Encrypted Virtualization (SEV) feature of AMD
  EPYC™ CPUs. Customer data will stay encrypted while it is used, indexed, queried, or
  trained on. Encryption keys are generated in hardware, per VM, and not exportable. Thanks
  to built-in hardware optimizations of both performance and security, there is no significant
  performance penalty to Confidential Computing workloads.`,
  audit: `**Note:** Confidential Computing is currently only supported on N2D machines. To learn more about types of N2D machines, visit https://cloud.google.com/compute/docs/machine-types#n2d_machine_types

  **From Console:**
  1. Go to the *VM instances* page by visiting: https://console.cloud.google.com/compute/instances.
  2. Click on the instance name to see its VM instance details page.
  3. Ensure that *Confidential VM service* is *Enabled*.

  **From Command Line:**

  1. For each instance in your project, get its metadata:

  gcloud compute instances describe INSTANCE_NAME --zone ZONE

  2. Ensure that *enableConfidentialCompute* is set to *true* for all instances with machine type starting with "n2d-".

          confidentialInstanceConfig:
            enableConfidentialCompute: true`,
  rationale: `Confidential Computing enables customers' sensitive code and other data encrypted in memory during processing. Google does not have access to the encryption keys. Confidential VM can help alleviate concerns about risk related to either dependency on Google infrastructure or Google insiders' access to customer data in the clear.`,
  remediation: `**NOTE:** Confidential Computing can only be enabled when an instance is created. You must delete the current instance and create a new one.

  **From Console:**

  1. Go to the VM instances page by visiting: https://console.cloud.google.com/compute/instances.
  2. Click *CREATE INSTANCE*.
  3. Fill out the desired configuration for your instance.
  4. Under the *Confidential VM service* section, check the option *Enable the Confidential Computing service on this VM instance*.
  5. Click *Create*.

  **From Command Line:**
  Create a new instance with Confidential Compute enabled.

      gcloud beta compute instances create INSTANCE_NAME --zone ZONE -- confidential-compute --maintenance-policy=TERMINATE`,
  references: [
    `https://cloud.google.com/compute/confidential-vm/docs/creating-cvm-instance`,
    `https://cloud.google.com/compute/confidential-vm/docs/about-cvm`,
    `https://cloud.google.com/confidential-computing`,
  ],
  gql: `{
    querygcpVmInstance {
      id
      __typename
      confidentialInstanceConfig {
        enableConfidentialCompute
      }
    }
  }`,
  resource: 'querygcpVmInstance[*]',
  severity: 'unknown',
  conditions: {
    path: '@.confidentialInstanceConfig.enableConfidentialCompute',
    equal: true,
  },
}
