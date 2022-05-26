export default {
  id: 'aws-nist-800-53-rev4-11.1',  
  title: 'AWS NIST 11.1 ECS task definitions should limit memory usage for containers',
  
  description: `Limiting memory usage for your ECS tasks allows you to avoid running out of memory because ECS stops placing tasks on the instance, and Docker kills any containers that try to go over the hard limit. Having no limit on memory usage can lead to issues where one container can easily make the whole system unstable and as a result unusable.
  
  Memory limits must be set through the *memory* property for each *ContainerDefinition* within the task definition. For more information about the *memory* property, see [ContainerDefinition](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html) in the ECS API Reference.`,
  
  audit: '',
  
  rationale: '',
  
  remediation: `**Console Remediation Steps**
  
  - Navigate to [ECS](https://console.aws.amazon.com/ecs/).
  - Select the Region that contains your task definition.
  - In the left pane, select Task Definitions.
  - Check the task definition and click Create new revision.
  - On the Create new revision of task definition page, make changes. For example, to change the existing container definitions (such as the container image, memory limits, or port mappings), select the container, make the changes, and then choose Update.
  - Select Create.
  - If your task definition is used in a service, update your service with the updated task definition and deactivate the previous task definition. For more information, see [Updating a service](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-service.html).
  
  **CLI Remediation Steps**
  
  - Create new task definition revision:
  
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
  
  - Update the service to use the new task definition:
  
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
      'https://aws.amazon.com/blogs/containers/how-amazon-ecs-manages-cpu-and-memory-resources/',
  ],
  gql: `{
    queryawsEcsTaskDefinition {
      id
      arn
      accountId
      __typename
      memory
    }    
  }`,
  resource: 'queryawsEcsTaskDefinition[*]',
  severity: 'medium',
  conditions: {
    path: '@.memory',
    in: ['0', '256', '512'],
  },
}