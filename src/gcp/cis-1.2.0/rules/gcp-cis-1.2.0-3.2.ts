export default {
  id: 'gcp-cis-1.2.0-3.2',
  description: 'GCP CIS 3.2 Ensure legacy networks do not exist for a project',
  audit: `For each Google Cloud Platform project,

  1. Set the project name in the Google Cloud Shell:
  
          gcloud config set project <Project-ID>
  
  2. List the networks configured in that project:
  
          gcloud compute networks list
  
  None of the listed networks should be in the *legacy* mode.`,
  rationale: `Legacy networks have a single network IPv4 prefix range and a single gateway IP address for the whole network. The network is global in scope and spans all cloud regions. Subnetworks cannot be created in a legacy network and are unable to switch from legacy to auto or custom subnet networks. Legacy networks can have an impact for high network traffic projects and are subject to a single point of contention or failure.`,
  remediation: `For each Google Cloud Platform project,

  1. Follow the documentation and create a non-legacy network suitable for the
      organization's requirements.
  
  2. Follow the documentation and delete the networks in the *legacy* mode.`,
  references: [
    `https://cloud.google.com/vpc/docs/using-legacy#creating_a_legacy_network`,
    `https://cloud.google.com/vpc/docs/using-legacy#deleting_a_legacy_network`,
  ],
  gql: `{
    querygcpNetwork {
      id
      __typename
      ipV4Range
    }
  }`,
  resource: 'querygcpNetwork[*]',
  severity: 'medium',
  conditions: {
    path: '@.ipV4Range',
    equal: null,
  },
}
