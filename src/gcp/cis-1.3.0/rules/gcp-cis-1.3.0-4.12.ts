export default {
  id: 'gcp-cis-1.3.0-4.12',
  title:
    'GCP CIS 4.12 Ensure the Latest Operating System Updates Are Installed On Your Virtual Machines in All Projects',
  description: `For the virtual machines where you manage the operating system in Infrastructure as a 
  Service (IaaS), you are responsible for keeping these operating systems and programs up to 
  date. There are multiple ways to manage updates yourself that would be difficult to fit into 
  one recommendation. Check the CIS Benchmarks for each of your Operating Systems as 
  well for potential solutions there. In this recommendation we will use a feature in Google 
  Cloud via its VM manager API to manage updates called Operating System Patch 
  Management (referred to OS Patch Management from here on out). This may requires 
  installing the OS Config API if it is not already installed. Also if you install custom operating 
  systems, they may not functionally support the local OS config agent required to gather 
  operating system patch information and issue update commands. These update commands 
  are the default Linux and Windows commands to install updates such as yum or apt. This 
  feature allows for a central management to issue those commands. OS Patch management 
  also does not host the updates itself, so your VMs will need to be public or be able to access 
  the internet. This is not the only Patch Management solution available to your organization 
  and you should weigh your needs before committing to using this.`,
  audit: `**Verifying that VM Manager and related services are installed on your Compute Operating Systems on a project by project basis
  
  Determine if OS Config API is Enabled for the Project**

  1. Navigate into a project. In the expanded hamburger menu located at the top left of the screen hover over "APIs & Services". Then in the menu right of that select "API Libraries"
  2. Search for "VM Manager (OS Config API) or scroll down in the left hand column and select the filter labeled "Compute" where it is the last listed. Open this API.
  3. Verify the blue button at the top is enabled.

  **Determine if VM Instances have correct metadata tags for OSConfig parsing**

  1. From the main Google Cloud console, open the hamburger menu in the top left. Mouse over Computer Engine to expand the menu next to it.
  2. Under the "Settings" heading, select "Metadata".
  3. In this view there will be a list of the project wide metadata tags for VMs. Determine if the tag "enable-osconfig" is set to "true".

  **Determine if the Operating System of VM Instances have the local OS-Config Agent running**

  There is no way to determine this from the Google Cloud console. The only way is to run 
  operating specific commands locally inside the operating system via remote connection. 
  For the sake of brevity of this recommendation please view the docs/troubleshooting/vm-manager/verify-setup 
  reference at the bottom of the page. If you initialized your VM 
  instance with a Google Supplied OS Image with a build date of later than v20200114 it will 
  have the service installed. You should still determine its status for proper operation.

  **Verify the service account you have setup for the project in Recommendation 4.1 is running**

  1. Go to the *VM instances* page by visiting: https://console.cloud.google.com/compute/instances.
  2. Click on each instance name to go to its *VM instance details* page.
  3. Under the section *Service Account*, take note of the service account
  4. Run the commands locally for your operating system that are located at the docs/troubleshooting/vm-manager/verify-setup#service-account-enabled reference located at the bottom of this page. They should return the name of your service account.

  **Determine if Instances can connect to public update hosting**

  Linux
  Debian Based Operating Systems

        sudo apt update

  The output should have a numbered list of lines with Hit: URL of updates.
  Redhat Based Operating Systems

        yum check-update

  The output should show a list of packages that have updates available.
  Windows

        ping http://windowsupdate.microsoft.com/

  The ping should successfully be delivered and received.

  **Determine if OS Config API is Enabled for the Project**

  1. In each project you wish to enable run the following command

        gcloud services list

  2. If osconfig.googleapis.com is in the left hand column it is enabled for this project.

  **Determine if VM Manager is Enabled for the Project**

  1. Within the project run the following command:

        gcloud compute instances os-inventory describe VM-NAME --zone=ZONE

  The output will look like

  INSTANCE_ID             INSTANCE_NAME  OS
  OSCONFIG_AGENT_VERSION  UPDATE_TIME
  29255009728795105    centos7  CentOS Linux 7 (Core)
  20210217.00-g1.el7    2021-04-12T22:19:36.559Z
  5138980234596718741  rhel-8   Red Hat Enterprise Linux 8.3 (Ootpa)
  20210316.00-g1.el8    2021-09-16T17:19:24Z
  7127836223366142250 windows Microsoft Windows Server 2019 Datacenter
  20210316.00.0+win@1 2021-09-16T17:13:18Z

  **Determine if VM Instances have correct metadata tags for OSConfig parsing**

  1. Select the project you want to view tagging in.
  
  Google Cloud Console

  1. From the main Google Cloud console, open the hamburger menu in the top left. Mouse over Computer Engine to expand the menu next to it.
  2. Under the "Settings" heading, select "Metadata".
  3. In this view there will be a list of the project wide metadata tags for Vms. Verify a tag of ‘enable-osconfig’ is in this list and it is set to ‘true’.



  **From Console:**
  1. Go to the *VM instances* page by visiting: https://console.cloud.google.com/compute/instances.
  2. Click on the instance name to see its VM instance details page.
  3. Ensure that *Confidential VM service* is *Enabled*.

  **From Command Line:**

  Run the following command to view instance data
  
        gcloud compute instances list --format="table(name,status,tags.list())"
  
  On each instance it should have a tag of ‘enable-osconfig’ set to ‘true’

  **Determine if the Operating System of VM Instances have the local OS-Config Agent running**

  There is no way to determine this from the Google Cloud CLI. The best way is to run the the 
  commands inside the operating system located at 'Check OS-Config agent is installed and 
  running' at the /docs/troubleshooting/vm-manager/verify-setup reference at the bottom 
  of the page. If you initialized your VM instance with a Google Supplied OS Image with a 
  build date of later than v20200114 it will have the service installed. You should still 
  determine its status.

  **Verify the service account you have setup for the project in Recommendation 4.1 is running**

  1. Go to the *VM instances* page by visiting: https://console.cloud.google.com/compute/instances.
  2. Click on each instance name to go to its VM *instance details* page.
  3. Under the section *Service Account*, take note of the service account
  4. View the compute/docs/troubleshooting/vm-manager/verify-setup#service-account-enabled resource at the bottom of the page for operating system specific commands to run locally.

  **Determine if Instances can connect to public update hosting**

  Linux
  Debian Based Operating Systems

        sudo apt update

  The output should have a numbered list of lines with Hit: URL of updates.
  Redhat Based Operating Systems

        yum check-update

  The output should show a list of packages that have updates available.
  Windows

        ping http://windowsupdate.microsoft.com/

  The ping should successfully be delivered and received.
`,
  rationale: 'Keeping an operating system up to date is the best way to secure against ever evolving known vulnerabilities and bugs in programs that can be used in cyber attacks by bad actors.',
  remediation: `**Enabling OS Patch Management on a Project by Project Basis
  
  Install OS Config API for the Project**

  1. Navigate into a project. In the expanded hamburger menu located at the top left of the screen hover over "APIs & Services". Then in the menu right of that select "API Libraries"
  2. Search for "VM Manager (OS Config API) or scroll down in the left hand column and select the filter labeled "Compute" where it is the last listed. Open this API.
  3. Click the blue 'Enable' button.

  **Add MetaData Tags for OSConfig Parsing**

  1. From the main Google Cloud console, open the hamburger menu in the top left. Mouse over Computer Engine to expand the menu next to it.
  2. Under the "Settings" heading, select "Metadata".
  3. In this view there will be a list of the project wide metadata tags for VMs. Click edit and 'add item' in the key column type 'enable-osconfig' and in the value column set it to 'true'.

  **From Command Line:**

  1. For project wide tagging, run the following command

        gcloud compute project-info add-metadata \
        --project <PROJECT_ID>\
        --metadata=enable-osconfig=TRUE

  Please see the reference /compute/docs/troubleshooting/vm-manager/verify- setup#metadata-enabled at the bottom for more options like instance specific tagging. Note: Adding a new tag via commandline may overwrite existing tags. You will need to do this at a time of low usage for the least impact.

  **Install and Start the Local OSConfig for Data Parsing**

  There is no way to centrally manage or start the Local OSConfig agent. Please view the reference of manage-os#agent-install to view specific operating system commands.

  **Setup a project wide Service Account**

  Please view Recommendation 4.1 to view how to setup a service account. Rerun the audit procedure to test if it has taken effect.

  **Enable NAT or Configure Private Google Access to allow Access to Public Update Hosting**

  For the sake of brevity, please see the attached resources to enable NAT or Private Google Access. Rerun the audit procedure to test if it has taken effect.

  **Install OS Config API for the Project**

  1. In each project you wish to audit run gcloud services enable osconfig.googleapis.com

  **Install and Start the Local OSConfig for Data Parsing**

  Please view the reference of manage-os#agent-install to view specific operating system commands.

  **Setup a project wide Service Account**

  Please view Recommendation 4.1 to view how to setup a service account. Rerun the audit procedure to test if it has taken effect.

  **Enable NAT or Configure Private Google Access to allow Access to Public Update Hosting**

  For the sake of brevity, please see the attached resources to enable NAT or Private Google Access. Rerun the audit procedure to test if it has taken effect.
  Determine if Instances can connect to public update hosting
  Linux
  Debian Based Operating Systems

        sudo apt update

  The output should have a numbered list of lines with Hit: URL of updates.
  Redhat Based Operating Systems

        yum check-update

  The output should show a list of packages that have updates available.
  Windows

        ping http://windowsupdate.microsoft.com/

  The ping should successfully be delivered and received.

  **Default Value:**

  By default most operating systems and programs do not update themselves. The Google Cloud VM Manager which is a dependency of the OS Patch management feature is installed on Google Built OS images with a build date of v20200114 or later. The VM manager is not enabled in a project by default and will need to be setup.
`,
  references: [
    'https://cloud.google.com/compute/docs/manage-os',
    'https://cloud.google.com/compute/docs/os-patch-management',
    'https://cloud.google.com/compute/docs/vm-manager',
    'https://cloud.google.com/compute/docs/images/os-details#vm-manager',
    'https://cloud.google.com/compute/docs/vm-manager#pricing',
    'https://cloud.google.com/compute/docs/troubleshooting/vm-manager/verify-setup',
    'https://cloud.google.com/compute/docs/instances/view-os-details#view-data-tools',
    'https://cloud.google.com/compute/docs/os-patch-management/create-patch-job',
    'https://cloud.google.com/nat/docs/set-up-network-address-translation',
    'https://cloud.google.com/vpc/docs/configure-private-google-access',
    'https://workbench.cisecurity.org/sections/811638/recommendations/1334335',
    'https://cloud.google.com/compute/docs/manage-os#agent-install',
    'https://cloud.google.com/compute/docs/troubleshooting/vm-manager/verify- setup#service-account-enabled',
    'https://cloud.google.com/compute/docs/os-patch-management#use-dashboard',
    'https://cloud.google.com/compute/docs/troubleshooting/vm-manager/verify-setup#metadata-enabled',
  ],
  severity: 'unknown',
}
