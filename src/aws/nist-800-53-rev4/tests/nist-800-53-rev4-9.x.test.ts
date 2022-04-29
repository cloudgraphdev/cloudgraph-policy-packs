import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_91 from '../rules/aws-nist-800-53-rev4-9.1'
import Aws_NIST_800_53_92 from '../rules/aws-nist-800-53-rev4-9.2'
import Aws_NIST_800_53_93 from '../rules/aws-nist-800-53-rev4-9.3'
import Aws_NIST_800_53_94 from '../rules/aws-nist-800-53-rev4-9.4'

export interface MountPoint {
  containerPath?: string
  readOnly?: boolean
}

export interface Capabilities {
  add: string[]
  drop: string[]
}

export interface LinuxParameters {
  capabilities: Capabilities
}

export interface ContainerDefinition {
  mountPoints?: MountPoint[]
  linuxParameters?: LinuxParameters
}

export interface Host {
  sourcePath: string
}

export interface Volume {
  host: Host
}

export interface QueryawsEcsTaskDefinition {
  id: string
  containerDefinitions?: ContainerDefinition[]
  volumes?: Volume[]
}

export interface NIS9xQueryResponse {
  queryawsEcsTaskDefinition?: QueryawsEcsTaskDefinition[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'NIST',
    })
  })

  describe('AWS NIST 9.1 ECS container definitions should not mount volumes with mount propagation set to shared', () => {
    const getTestRuleFixture = (containerPath: string): NIS9xQueryResponse => {
      return {
        queryawsEcsTaskDefinition: [
          {
            id: cuid(),
            containerDefinitions: [
              {
                mountPoints: [
                  {
                    containerPath,
                  },
                  {
                    containerPath: '/containerPath',
                  },
                ],
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS9xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_91 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with mount propagation NOT set to shared', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture('/data')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with mount propagation set to shared', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture('/data:shared')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 9.2 ECS task definitions should mount the container’s root filesystem as read-only', () => {
    const getTestRuleFixture = (readOnly: boolean): NIS9xQueryResponse => {
      return {
        queryawsEcsTaskDefinition: [
          {
            id: cuid(),
            containerDefinitions: [
              {
                mountPoints: [
                  {
                    readOnly,
                  },
                  {
                    readOnly: true,
                  },
                ],
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS9xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_92 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when task definitions has mount the container’s root filesystem as read-only', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there any task definitions that has NOT mount the container’s root filesystem as read-only', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 9.3 ECS task definitions should not add Linux capabilities beyond defaults and should drop NET_RAW', () => {
    const getTestRuleFixture = (
      add: string[],
      drop: string[]
    ): NIS9xQueryResponse => {
      return {
        queryawsEcsTaskDefinition: [
          {
            id: cuid(),
            containerDefinitions: [
              {
                linuxParameters: {
                  capabilities: {
                    add,
                    drop,
                  },
                },
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS9xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_93 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when task definitions drop ‘NET_RAW’ and do not add any other capabilities', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture([], ['NET_RAW'])
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when task definitions drop ‘ALL’  capabilities', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture(
        ['AUDIT_CONTROL'],
        ['ALL']
      )
      await testRule(data, Result.PASS)
    })

    test('Security Issue when task definitions add Linux capabilities allows users to grant some superuser permission', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture(
        ['AUDIT_CONTROL', 'AUDIT_WRITE'],
        ['NET_RAW']
      )
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 9.4 ECS task definitions should not mount sensitive host system directories', () => {
    const getTestRuleFixture = (sourcePath: string): NIS9xQueryResponse => {
      return {
        queryawsEcsTaskDefinition: [
          {
            id: cuid(),
            volumes: [
              {
                host: {
                  sourcePath,
                },
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS9xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_94 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when task definitions not mount sensitive host system directories', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture('/something')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when task definitions mount "/" sensitive host system directory', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture('/')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when task definitions mount "/boot" sensitive host system directory', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture('/boot/something')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when task definitions mount "/dev" sensitive host system directory', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture('/dev')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when task definitions mount "/etc" sensitive host system directory', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture('/etc/something/something')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when task definitions mount "/lib" sensitive host system directory', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture('/lib')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when task definitions mount "/proc" sensitive host system directory', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture('/proc')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when task definitions mount "/sys" sensitive host system directory', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture('/sys')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when task definitions mount "/usr" sensitive host system directory', async () => {
      const data: NIS9xQueryResponse = getTestRuleFixture('/usr')
      await testRule(data, Result.FAIL)
    })
  })
})
