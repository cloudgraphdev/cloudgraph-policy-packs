export default {
  id: 'aws-nist-800-53-rev4-9.4',  
  title: 'AWS NIST 9.4 ECS task definitions should not mount sensitive host system directories',
  
  description: `Mounting sensitive host system directories in an ECS task definition grants privileges beyond the boundaries of a container. This creates unnecessary risk and increases the attack surface of the container.
  
  The following are considered sensitive host directories as defined by the CIS Docker Benchmark v1.2.0:
  
  - /
  - /boot
  - /dev
  - /etc
  - /lib
  - /proc
  - /sys
  - /usr
  
  Host mounts are specified by defining a volume in the task definition with a **host** property. For more information about about volumes and host mounts, see [Volume](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_Volume.html) and [HostVolumeProperties](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_HostVolumeProperties.html) in the ECS API reference.`,
  
  audit: '',
  
  rationale: 'If sensitive directories are mounted in read-write mode, it could be possible to make changes to files within them. This has obvious security implications and should be avoided.',
  
  remediation: `**Console Remediation Steps**
  
  - Navigate to [ECS](https://console.aws.amazon.com/ecs/).
  - Select the Region that contains your task definition.
  - In the left pane, select Task Definitions.
  - Check the task definition and click Create new revision.
  - On the Create new revision of task definition page, make changes. For example, to change the existing container definitions (such as the container image, memory limits, or port mappings), select the container, make the changes, and then choose Update.
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
      volumes {
        host {
          sourcePath
        }
      }
    }
  }`,
  resource: 'queryawsEcsTaskDefinition[*]',
  severity: 'high',
  conditions: {  
    not: {
      path: '@.volumes',
      array_any: {
        path: '[*].host.sourcePath',
        match: /(^\/$|^\/boot$|^\/boot\/.*|^\/dev$|^\/dev\/.*|^\/etc$|^\/etc\/.*|^\/lib$|^\/lib\/.*|^\/proc$|^\/proc\/.*|^\/sys$|^\/sys\/.*|^\/usr$|^\/usr\/.*)/,
      },
    }
  },
}
