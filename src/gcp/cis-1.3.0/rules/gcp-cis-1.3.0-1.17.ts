/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
/* eslint-disable @typescript-eslint/no-explicit-any */

export default {
  id: 'gcp-cis-1.3.0-1.17',
  title: 'GCP CIS 1.16 Ensure Essential Contacts is Configured for Organization',
  description:
    'When you use Dataproc, cluster and job data is stored on Persistent Disks (PDs) associated with the Compute Engine VMs in your cluster and in a Cloud Storage staging bucket. This PD and bucket data is encrypted using a Google-generated data encryption key (DEK) and key encryption key (KEK). The CMEK feature allows you to create, use, and revoke the key encryption key (KEK). Google still controls the data encryption key (DEK).',
  audit: `**From Console:**
  
  1. Login to the GCP Console and navigate to the Dataproc Cluster page by visiting:

          https://console.cloud.google.com/dataproc/clusters.

  2. Select the project from the project dropdown list.
  3. On the Dataproc Clusters page, select the cluster and click on the Name attribute value that you want to examine.
  4. On the details page, select the Configurations tab.
  5. On the Configurations tab, check the Encryption type configuration attribute value. If the value is set to Google-managed key, then Dataproc Cluster is not encrypted with Customer managed encryption keys.
  
  Repeat step no. 3 - 5 for other Dataproc Clusters available in the selected project.
  
  6. Change the project from the project dropdown list and repeat the audit procedure for other projects.

  **From Command Line:**

  1. Run clusters list command to list all the Dataproc Clusters available in the region:

          gcloud dataproc clusters list --region='us-central1'

  2. Run clusters describe command to get the key details of the selected cluster:

          gcloud dataproc clusters describe <cluster_name> --region=us-central1 --flatten=config.encryptionConfig.gcePdKmsKeyName
          
  3. If the above command output return "null", then the selected cluster is not encrypted with Customer managed encryption keys.
  4. Repeat step no. 2 and 3 for other Dataproc Clusters available in the selected region. Change the region by updating --region and repeat step no. 2 for other clusters available in the project. Change the project by running the below command and repeat the audit procedure for other Dataproc clusters available in other projects:

          gcloud config set project <project_ID>"
  `,
  rationale:
    'Many Google Cloud services, such as Cloud Billing, send out notifications to share important information with Google Cloud users. By default, these notifications are sent to members with certain Identity and Access Management (IAM) roles. With Essential Contacts, you can customize who receives notifications by providing your own list of contacts.',
  remediation: `**From Console:**
  1. Login to the GCP Console and navigate to the Dataproc Cluster page by visiting
      
          https://console.cloud.google.com/dataproc/clusters.

  2. Select the project from the projects dropdown list.
  3. On the *Dataproc Cluster* page, click on the *Create Cluster* to create a new cluster with Customer managed encryption keys.
  4. On *Create a cluster* page, perform below steps:
    • Inside *Set up cluster* section perform below steps:
      -In the *Name* textbox, provide a name for your cluster.
        o From *Location* select the location in which you want to deploy a cluster.
        o Configure other configurations as per your requirements.
    • Inside *Configure Nodes* and *Customize cluster* section configure the settings as per your requirements.
    • Inside *Manage security* section, perform below steps:
      o From *Encryption*, select *Customer-managed key*.
      o Select a customer-managed key from dropdown list.
      o Ensure that the selected KMS Key have Cloud KMS CryptoKey Encrypter/Decrypter role assign to Dataproc Cluster service account ("serviceAccount:service-<project_number>@computesystem.iam.gserviceaccount.com").
      o Click on *Create* to create a cluster.
    • Once the cluster is created migrate all your workloads from the older cluster to the new cluster and delete the old cluster by performing the below steps:
      o On the *Clusters* page, select the old cluster and click on *Delete cluster*.
      o On the *Confirm deletion* window, click on *Confirm* to delete the cluster.
      o Repeat step above for other Dataproc clusters available in the selected project.
    • Change the project from the project dropdown list and repeat the remediation procedure for other Dataproc clusters available in other projects.


  **From Command Line:**

  Before creating cluster ensure that the selected KMS Key have Cloud KMS CryptoKey Encrypter/Decrypter role assign to Dataproc Cluster service account ("serviceAccount:service-<project_number>@compute-system.iam.gserviceaccount.com").
  Run clusters create command to create new cluster with customer-managed key:

        gcloud dataproc clusters create <cluster_name> --region=us-central1 --gce-pdkms-key=<key_resource_name>

  The above command will create a new cluster in the selected region.
  Once the cluster is created migrate all your workloads from the older cluster to the new cluster and Run clusters delete command to delete cluster:

        gcloud dataproc clusters delete <cluster_name> --region=us-central1

  Repeat step no. 1 to create a new Dataproc cluster.
  Change the project by running the below command and repeat the remediation procedure for other projects:

        gcloud config set project <project_ID>"
  `,
  references: [
    'https://cloud.google.com/docs/security/encryption/default-encryption',
  ],
  gql: `{
    querygcpDataprocCluster {
      id
      __typename
      config{
        encryptionConfigGcePdKmsKeyName
      }
    }
  }`,
  resource: 'querygcpDataprocCluster[*]',
  severity: 'unknown',
  conditions: {
    path: '@.config.encryptionConfigGcePdKmsKeyName',
    isEmpty: false,
  }
}
