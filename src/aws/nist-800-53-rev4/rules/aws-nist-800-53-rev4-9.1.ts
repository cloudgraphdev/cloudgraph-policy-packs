export default {
  id: 'aws-nist-800-53-rev4-9.1',
  title: 'AWS NIST 9.1 ECS container definitions should not mount volumes with mount propagation set to shared',
  
  description: `A shared mount is replicated at all mounts and changes made at any mount point are propagated to all other mount points. Mounting a volume in shared mode does not restrict any other container from mounting and making changes to that volume.
  
  The bind propagation setting is not officially supported by the ECS API. However, [it is still possible to modify this setting](https://github.com/aws/containers-roadmap/issues/362) by suffixing the _**containerPath**_ property of a mount point with a bind propagation mode. We recommend against modifying this property so that the default **rprivate** mode is used. We enforce that neither the **shared** nor **rshared** modes are used. For more information about bind propagation, see [Configure bind propagation](https://docs.docker.com/storage/bind-mounts/#configure-bind-propagation) in the Docker documentation.`,
  
  audit: '',
  
  rationale: '',
  
  remediation: `**Console Remediation Steps**
  
  - Navigate to [ECS](https://console.aws.amazon.com/ecs/).
  - Select the Region that contains your task definition.
  - In the left pane, select Task Definitions.
  - Check the task definition and click Create new revision.
  - On the Create new revision of task definition page, make changes. For example, to change the existing container definitions (such as the container image, memory - limits, or port mappings), select the container, make the changes, and then choose Update.
  - Select Create.
  - If your task definition is used in a service, update your service with the updated task definition and deactivate the previous task definition. For more information, see [Updating a service](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-service.html).
  
  **CLI Remediation Steps**
  
  Create new task definition revision:
  
      aws ecs register-task-definition
      --family <value>
      [--task-role-arn <value>]
      [--execution-role-arn <value>]
      [--network-mode <value>]
      --container-definitions <value>
      [--volumes <value>]
      [--placement-constraints <value>]
      [--requires-compatibilities <value>]
      [--cpu <value>]
      [--memory <value>]
      [--tags <value>]
      [--pid-mode <value>]
      [--ipc-mode <value>]
      [--proxy-configuration <value>]
      [--inference-accelerators <value>]
      [--cli-input-json | --cli-input-yaml]
      [--generate-cli-skeleton <value>]
  
  Update the service to use the new task definition:
  
      aws ecs update-service
      [--cluster <value>]
      --service <value>
      [--desired-count <value>]
      [--task-definition <value>]
      [--capacity-provider-strategy <value>]
      [--deployment-configuration <value>]
      [--network-configuration <value>]
      [--placement-constraints <value>]
      [--placement-strategy <value>]
      [--platform-version <value>]
      [--force-new-deployment | --no-force-new-deployment]
      [--health-check-grace-period-seconds <value>]
      [--cli-input-json | --cli-input-yaml]
      [--generate-cli-skeleton <value>]`,
  
  references: [
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-service.html',
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-task-definition.html',
      'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ecs/register-task-definition.html',
      'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ecs/update-service.html',
  ],
  gql: `{
    queryawsEcsTaskDefinition {
      id
      arn
      accountId
       __typename
      containerDefinitions {
        mountPoints {
          containerPath
        }
      }
    }
  }`,
  resource: 'queryawsEcsTaskDefinition[*]',
  severity: 'medium',
  conditions: {  
    not: {
      path: '@.containerDefinitions',
      array_any: {
        path: '[*].mountPoints',
        array_any: {
          path: '[*].containerPath',
          match: /shared/,
        },
      },
    },
  },
}
