import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_81 from '../rules/aws-nist-800-53-rev4-8.1'
import Aws_NIST_800_53_82 from '../rules/aws-nist-800-53-rev4-8.2'
import Aws_NIST_800_53_83 from '../rules/aws-nist-800-53-rev4-8.3'
import Aws_NIST_800_53_84 from '../rules/aws-nist-800-53-rev4-8.4'
import Aws_NIST_800_53_85 from '../rules/aws-nist-800-53-rev4-8.5'
import Aws_NIST_800_53_86 from '../rules/aws-nist-800-53-rev4-8.6'
import Aws_NIST_800_53_87 from '../rules/aws-nist-800-53-rev4-8.7'
import Aws_NIST_800_53_88 from '../rules/aws-nist-800-53-rev4-8.8'
import Aws_NIST_800_53_89 from '../rules/aws-nist-800-53-rev4-8.9'
import Aws_NIST_800_53_810 from '../rules/aws-nist-800-53-rev4-8.10'
import Aws_NIST_800_53_811 from '../rules/aws-nist-800-53-rev4-8.11'
import Aws_NIST_800_53_812 from '../rules/aws-nist-800-53-rev4-8.12'
import Aws_NIST_800_53_813 from '../rules/aws-nist-800-53-rev4-8.13'
import Aws_NIST_800_53_814 from '../rules/aws-nist-800-53-rev4-8.14'
import Aws_NIST_800_53_815 from '../rules/aws-nist-800-53-rev4-8.15'
import Aws_NIST_800_53_816 from '../rules/aws-nist-800-53-rev4-8.16'
import Aws_NIST_800_53_817 from '../rules/aws-nist-800-53-rev4-8.17'
import Aws_NIST_800_53_818 from '../rules/aws-nist-800-53-rev4-8.18'
import Aws_NIST_800_53_819 from '../rules/aws-nist-800-53-rev4-8.19'
import Aws_NIST_800_53_820 from '../rules/aws-nist-800-53-rev4-8.20'
import Aws_NIST_800_53_821 from '../rules/aws-nist-800-53-rev4-8.21'
import Aws_NIST_800_53_822 from '../rules/aws-nist-800-53-rev4-8.22'
import Aws_NIST_800_53_823 from '../rules/aws-nist-800-53-rev4-8.23'
import Aws_NIST_800_53_824 from '../rules/aws-nist-800-53-rev4-8.24'
import Aws_NIST_800_53_825 from '../rules/aws-nist-800-53-rev4-8.25'
import Aws_NIST_800_53_826 from '../rules/aws-nist-800-53-rev4-8.26'
import Aws_NIST_800_53_827 from '../rules/aws-nist-800-53-rev4-8.27'
import Aws_NIST_800_53_828 from '../rules/aws-nist-800-53-rev4-8.28'
import Aws_NIST_800_53_829 from '../rules/aws-nist-800-53-rev4-8.29'
import Aws_NIST_800_53_830 from '../rules/aws-nist-800-53-rev4-8.30'
import Aws_NIST_800_53_831 from '../rules/aws-nist-800-53-rev4-8.31'
import Aws_NIST_800_53_832 from '../rules/aws-nist-800-53-rev4-8.32'
import Aws_NIST_800_53_833 from '../rules/aws-nist-800-53-rev4-8.33'
import Aws_NIST_800_53_834 from '../rules/aws-nist-800-53-rev4-8.34'
import Aws_NIST_800_53_835 from '../rules/aws-nist-800-53-rev4-8.35'
import Aws_NIST_800_53_836 from '../rules/aws-nist-800-53-rev4-8.36'
import Aws_NIST_800_53_837 from '../rules/aws-nist-800-53-rev4-8.37'
import Aws_NIST_800_53_838 from '../rules/aws-nist-800-53-rev4-8.38'
import Aws_NIST_800_53_839 from '../rules/aws-nist-800-53-rev4-8.39'
import Aws_NIST_800_53_840 from '../rules/aws-nist-800-53-rev4-8.40'
import Aws_NIST_800_53_841 from '../rules/aws-nist-800-53-rev4-8.41'
import Aws_NIST_800_53_842 from '../rules/aws-nist-800-53-rev4-8.42'
import Aws_NIST_800_53_843 from '../rules/aws-nist-800-53-rev4-8.43'
import Aws_NIST_800_53_844 from '../rules/aws-nist-800-53-rev4-8.44'
import Aws_NIST_800_53_845 from '../rules/aws-nist-800-53-rev4-8.45'

const ipV4WildcardAddress = '0.0.0.0/0'
const ipV6WildcardAddress = '::/0'

export interface InboundRule {
  source?: string
  toPort?: number | null
  fromPort?: number | null
  protocol?: string
}

export interface OutboundRule {
  destination?: string
  toPort?: number | null
  fromPort?: number | null
  protocol?: string
}

export interface QueryawsSecurityGroup {
  id: string
  inboundRules?: InboundRule[]
  outboundRules?: OutboundRule[]
}
export interface QueryawsElb {
  id: string
  securityGroups: QueryawsSecurityGroup[]
}

export interface QueryawsEc2 {
  id: string
  securityGroups: QueryawsSecurityGroup[]
}

export interface QueryawsRdsDbInstance {
  id: string
  securityGroups: QueryawsSecurityGroup[]
}

export interface QueryawsNetworkAcl {
  id: string
  inboundRules?: InboundRule[]
  outboundRules?: OutboundRule[]
}
export interface NIS8xQueryResponse {
  queryawsSecurityGroup?: QueryawsSecurityGroup[]
  queryawsElb?: QueryawsElb[]
  queryawsEc2?: QueryawsEc2[]
  queryawsRdsDbInstance?: QueryawsRdsDbInstance[]
  queryawsNetworkAcl?: QueryawsNetworkAcl[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'NIST',
    })
  })

  const testRule = async (
    fromPort: number | null ,
    toPort: number | null,
    sourceAddress: string,
    rule: Rule,
    expectedResult: Result,
    includeRandomValidData = false
  ): Promise<void> => {
    // Arrange
    const validInboundRule = {
      toPort: 123,
      fromPort: 456,
      source: '10.10.10.10/16',
    }

    const data: NIS8xQueryResponse = {
      queryawsSecurityGroup: [
        {
          id: cuid(),
          inboundRules: [
            {
              toPort,
              fromPort,
              source: sourceAddress,
            },
          ],
        },
      ],
    }

    if (includeRandomValidData) {
      data.queryawsSecurityGroup?.[0].inboundRules?.push(validInboundRule)
      data.queryawsSecurityGroup?.push({
        id: cuid(),
        inboundRules: [validInboundRule, validInboundRule],
      })
    }

    // Act
    const [processedRule] = await rulesEngine.processRule(rule, { ...data })

    // Asserts
    expect(processedRule.result).toBe(expectedResult)
  }

  const testSecurityGroupRule = (
    rule: Rule,
    fromPort: number,
    toPort: number
  ): void => {
    test(`No Security Issue when there is an inbound rule with a random IPv4 address and port ${fromPort}`, async () => {
      await testRule(fromPort, toPort, '10.10.10.10/16', rule, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wildcard address and port 80', async () => {
      await testRule(80, 80, ipV4WildcardAddress, rule, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and port 80', async () => {
      await testRule(80, 80, ipV6WildcardAddress, rule, Result.PASS)
    })

    test(`No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port ${fromPort}`, async () => {
      await testRule(
        fromPort + 100,
        fromPort + 200,
        '10.10.10.10/16',
        rule,
        Result.PASS
      )
    })

    test(`No Security Issue when there is an inbound rule with IPv4 wildcard address and a port range not including the port ${fromPort}`, async () => {
      await testRule(
        fromPort + 100,
        fromPort + 200,
        ipV4WildcardAddress,
        rule,
        Result.PASS
      )
    })

    test(`No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not including the port ${fromPort}`, async () => {
      await testRule(
        fromPort + 100,
        fromPort + 200,
        ipV6WildcardAddress,
        rule,
        Result.PASS
      )
    })

    test(`No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not including the port ${fromPort} (multiple values)`, async () => {
      await testRule(
        fromPort + 100,
        fromPort + 200,
        ipV6WildcardAddress,
        rule,
        Result.PASS,
        true
      )
    })

    test(`Security Issue when IPv4 wildcard address and port ${fromPort}`, async () => {
      await testRule(fromPort, toPort, ipV4WildcardAddress, rule, Result.FAIL)
    })

    test(`Security Issue when IPv6 wildcard address and port ${fromPort}`, async () => {
      await testRule(fromPort, toPort, ipV6WildcardAddress, rule, Result.FAIL)
    })

    test(`Security Issue when IPv4 wildcard address and port ${fromPort} (multiple values)`, async () => {
      await testRule(
        fromPort,
        toPort,
        ipV4WildcardAddress,
        rule,
        Result.FAIL,
        true
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and no port range is specified', async () => {
      await testRule(
        null,
        null,
        ipV4WildcardAddress,
        rule,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and no port range is specified', async () => {
      await testRule(
        null,
        null,
        ipV6WildcardAddress,
        rule,
        Result.FAIL
      )
    })

    test(`Security Issue when there is an inbound rule with IPv4 wildcard address and port range includes the port ${fromPort}`, async () => {
      await testRule(0, fromPort + 100, ipV4WildcardAddress, rule, Result.FAIL)
    })

    test(`Security Issue when there is an inbound rule with IPv6 wildcard address and port range includes the port ${fromPort}`, async () => {
      await testRule(0, fromPort + 100, ipV6WildcardAddress, rule, Result.FAIL)
    })

    test('No Security Issue when there is an inbound rule with security group as source', async () => {
      await testRule(null, null, 'sg-049c76f349f62e4eb', rule, Result.PASS)
    })
  }

  describe('AWS NIST 8.1 ELB listener security groups should not be set to TCP all', () => {
    const test81Rule = async (
      inboundRules?: InboundRule[],
      outboundRules?: OutboundRule[],
      expectedResult?: Result,
      includeRandomValidData = false
    ): Promise<void> => {
      // Arrange
      const validInboundRule = {
        toPort: 123,
        fromPort: 456,
        source: '10.10.10.10/16',
      }
  
      const data: NIS8xQueryResponse = {
        queryawsElb: [
          {
            id: cuid(),
            securityGroups: [
              {
                id: cuid(),
                inboundRules,
                outboundRules,
              },
            ],
          }
        ],
      }
  
      if (includeRandomValidData) {
        data.queryawsElb?.[0].securityGroups?.[0].inboundRules?.push(validInboundRule)
        data.queryawsElb?.[0].securityGroups?.push({
          id: cuid(),
          inboundRules: [validInboundRule, validInboundRule],
        })
      }
  
      // Act
      const [processedRule] = await rulesEngine.processRule(Aws_NIST_800_53_81 as Rule, { ...data })
  
      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are an inbound and outbound rule that not allows all ports range', async () => {
      const inboundRules: InboundRule[] = [ { fromPort: 0,  toPort: 1000 } as InboundRule] 
      const outboundRules: OutboundRule[] = [ { fromPort: 2000,  toPort: 3000 } as OutboundRule] 
      await test81Rule(inboundRules, outboundRules, Result.PASS)
    })

    test('Security Issue when there are an inbound and outbound rule that allows all ports range', async () => {
      const inboundRules: InboundRule[] = [ { fromPort: null,  toPort: null } as InboundRule] 
      const outboundRules: OutboundRule[] = [ { fromPort: 0,  toPort: 65535 } as OutboundRule] 
      await test81Rule(inboundRules, outboundRules, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule that allows all ports range', async () => {
      const inboundRules: InboundRule[] = [ { fromPort: 0,  toPort: 65535 } as InboundRule] 
      const outboundRules: OutboundRule[] = [ { fromPort: 2000,  toPort: 3000 } as OutboundRule] 
      await test81Rule(inboundRules, outboundRules, Result.FAIL)
    })

    test('Security Issue when there is an outbound rule that allows all ports range', async () => {
      const inboundRules: InboundRule[] = [ { fromPort: 2000,  toPort: 3000 } as InboundRule] 
      const outboundRules: OutboundRule[] = [ { fromPort: 0,  toPort: 65535 } as OutboundRule] 
      await test81Rule(inboundRules, outboundRules, Result.FAIL)
    })

    test('No Security Issue when there is an inbound and outbound rule with security group as source', async () => {
      const inboundRules: InboundRule[] = [ { source: 'sg-049c76f349f62e4eb', fromPort: null,  toPort: null } as InboundRule] 
      const outboundRules: OutboundRule[] = [ { source: 'sg-049c76f349f62e4eb', fromPort: null,  toPort: null } as OutboundRule] 
      await test81Rule(inboundRules, outboundRules, Result.PASS)
    })
  })

  describe('AWS NIST 8.2 VPC default security group should restrict all traffic', () => {
    const getTestRuleFixture = (
      source: string,
      destination: string
    ): NIS8xQueryResponse => {
      return {
        queryawsSecurityGroup: [
          {
            id: cuid(),
            inboundRules: [
              {
                source,
              },
            ],
            outboundRules: [
              {
                destination,
              },
            ],
          },
        ],
      }
    }

    // Act
    const test82Rule = async (
      data: NIS8xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_82 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is not an inbound/outbound rules with the wildcard addresses', async () => {
      const data: NIS8xQueryResponse = getTestRuleFixture(
        '10.10.10.10/16',
        '2001:db8:3333:4444:5555:6666:7777:8888'
      )
      await test82Rule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a IPv4 wildcard address', async () => {
      const data: NIS8xQueryResponse = getTestRuleFixture(
        ipV4WildcardAddress,
        ''
      )
      await test82Rule(data, Result.FAIL)
    })
    test('Security Issue when there is an inbound rule with a IPv6 wildcard address', async () => {
      const data: NIS8xQueryResponse = getTestRuleFixture(
        ipV6WildcardAddress,
        ''
      )
      await test82Rule(data, Result.FAIL)
    })
    test('Security Issue when there is an outbound rule with a IPv4 wildcard address', async () => {
      const data: NIS8xQueryResponse = getTestRuleFixture(
        '',
        ipV4WildcardAddress
      )
      await test82Rule(data, Result.FAIL)
    })
    test('Security Issue when there is an outbound rule with a IPv6 wildcard address', async () => {
      const data: NIS8xQueryResponse = getTestRuleFixture(
        '',
        ipV6WildcardAddress
      )
      await test82Rule(data, Result.FAIL)
    })
    test('Security Issue when there is an inbound and an outbound rule with a IPv4 wildcard address', async () => {
      const data: NIS8xQueryResponse = getTestRuleFixture(
        ipV4WildcardAddress,
        ipV4WildcardAddress
      )
      await test82Rule(data, Result.FAIL)
    })
    test('Security Issue when there is an inbound and an outbound rule with a IPv6 wildcard address', async () => {
      const data: NIS8xQueryResponse = getTestRuleFixture(
        ipV6WildcardAddress,
        ipV6WildcardAddress
      )
      await test82Rule(data, Result.FAIL)
    })

    test('No Security Issue when there is an inbound rule with security group as source', async () => {
      const data: NIS8xQueryResponse = getTestRuleFixture(
        'sg-049c76f349f62e4eb',
        ''
      )
      await test82Rule(data, Result.PASS)
    })

    test('No Security Issue when there is an outbound rule with security group as source', async () => {
      const data: NIS8xQueryResponse = getTestRuleFixture(
        '',
        'sg-049c76f349f62e4eb'
      )
      await test82Rule(data, Result.PASS)
    })
  })

  describe('AWS NIST 8.3 VPC network ACLs should not allow ingress from 0.0.0.0/0 to TCP/UDP port 22', () => {
    const test83Rule = async (
      fromPort: number | undefined,
      toPort: number | undefined,
      sourceAddress: string,
      expectedResult: Result,
      includeRandomValidData = false
    ): Promise<void> => {
      // Arrange
      const validInboundRule = {
        toPort: 123,
        fromPort: 456,
        source: '10.10.10.10/16',
      }
  
      const data: NIS8xQueryResponse = {
        queryawsNetworkAcl: [
          {
            id: cuid(),
            inboundRules: [
              {
                toPort,
                fromPort,
                source: sourceAddress,
              },
            ],
          },
        ],
      }
  
      if (includeRandomValidData) {
        data.queryawsNetworkAcl?.[0].inboundRules?.push(validInboundRule)
        data.queryawsNetworkAcl?.push({
          id: cuid(),
          inboundRules: [validInboundRule, validInboundRule],
        })
      }
  
      // Act
      const [processedRule] = await rulesEngine.processRule(Aws_NIST_800_53_83 as Rule, { ...data })
  
      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    const fromPort = 22
    const toPort = 22

    test(`No Security Issue when there is an inbound rule with a random IPv4 address and port ${fromPort}`, async () => {
      await test83Rule(fromPort, toPort, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wildcard address and port 80', async () => {
      await test83Rule(80, 80, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and port 80', async () => {
      await test83Rule(80, 80, ipV6WildcardAddress, Result.PASS)
    })

    test(`No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port ${fromPort}`, async () => {
      await test83Rule(
        fromPort + 100,
        fromPort + 200,
        '10.10.10.10/16',
        Result.PASS
      )
    })

    test(`No Security Issue when there is an inbound rule with IPv4 wildcard address and a port range not including the port ${fromPort}`, async () => {
      await test83Rule(
        fromPort + 100,
        fromPort + 200,
        ipV4WildcardAddress,
        Result.PASS
      )
    })

    test(`No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not including the port ${fromPort}`, async () => {
      await test83Rule(
        fromPort + 100,
        fromPort + 200,
        ipV6WildcardAddress,
        Result.PASS
      )
    })

    test(`No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not including the port ${fromPort} (multiple values)`, async () => {
      await test83Rule(
        fromPort + 100,
        fromPort + 200,
        ipV6WildcardAddress,
        Result.PASS,
        true
      )
    })

    test(`Security Issue when IPv4 wildcard address and port ${fromPort}`, async () => {
      await test83Rule(fromPort, toPort, ipV4WildcardAddress, Result.FAIL)
    })

    test(`Security Issue when IPv6 wildcard address and port ${fromPort}`, async () => {
      await test83Rule(fromPort, toPort, ipV6WildcardAddress, Result.FAIL)
    })

    test(`Security Issue when IPv4 wildcard address and port ${fromPort} (multiple values)`, async () => {
      await test83Rule(
        fromPort,
        toPort,
        ipV4WildcardAddress,
        Result.FAIL,
        true
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and no port range is specified', async () => {
      await test83Rule(
        undefined,
        undefined,
        ipV4WildcardAddress,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and no port range is specified', async () => {
      await test83Rule(
        undefined,
        undefined,
        ipV6WildcardAddress,
        Result.FAIL
      )
    })

    test(`Security Issue when there is an inbound rule with IPv4 wildcard address and port range includes the port ${fromPort}`, async () => {
      await test83Rule(0, fromPort + 100, ipV4WildcardAddress, Result.FAIL)
    })

    test(`Security Issue when there is an inbound rule with IPv6 wildcard address and port range includes the port ${fromPort}`, async () => {
      await test83Rule(0, fromPort + 100, ipV6WildcardAddress, Result.FAIL)
    })

    test('No Security Issue when there is an inbound rule with security group as source', async () => {
      await test83Rule(undefined, undefined, 'sg-049c76f349f62e4eb', Result.PASS)
    })
  })

  describe('AWS NIST 8.4 VPC network ACLs should not allow ingress from 0.0.0.0/0 to TCP/UDP port 3389', () => {
    const test84Rule = async (
      fromPort: number | undefined,
      toPort: number | undefined,
      sourceAddress: string,
      expectedResult: Result,
      includeRandomValidData = false
    ): Promise<void> => {
      // Arrange
      const validInboundRule = {
        toPort: 123,
        fromPort: 456,
        source: '10.10.10.10/16',
      }
  
      const data: NIS8xQueryResponse = {
        queryawsNetworkAcl: [
          {
            id: cuid(),
            inboundRules: [
              {
                toPort,
                fromPort,
                source: sourceAddress,
              },
            ],
          },
        ],
      }
  
      if (includeRandomValidData) {
        data.queryawsNetworkAcl?.[0].inboundRules?.push(validInboundRule)
        data.queryawsNetworkAcl?.push({
          id: cuid(),
          inboundRules: [validInboundRule, validInboundRule],
        })
      }
  
      // Act
      const [processedRule] = await rulesEngine.processRule(Aws_NIST_800_53_84 as Rule, { ...data })
  
      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    const fromPort = 3389
    const toPort = 3389

    test(`No Security Issue when there is an inbound rule with a random IPv4 address and port ${fromPort}`, async () => {
      await test84Rule(fromPort, toPort, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wildcard address and port 80', async () => {
      await test84Rule(80, 80, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and port 80', async () => {
      await test84Rule(80, 80, ipV6WildcardAddress, Result.PASS)
    })

    test(`No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port ${fromPort}`, async () => {
      await test84Rule(
        fromPort + 100,
        fromPort + 200,
        '10.10.10.10/16',
        Result.PASS
      )
    })

    test(`No Security Issue when there is an inbound rule with IPv4 wildcard address and a port range not including the port ${fromPort}`, async () => {
      await test84Rule(
        fromPort + 100,
        fromPort + 200,
        ipV4WildcardAddress,
        Result.PASS
      )
    })

    test(`No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not including the port ${fromPort}`, async () => {
      await test84Rule(
        fromPort + 100,
        fromPort + 200,
        ipV6WildcardAddress,
        Result.PASS
      )
    })

    test(`No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not including the port ${fromPort} (multiple values)`, async () => {
      await test84Rule(
        fromPort + 100,
        fromPort + 200,
        ipV6WildcardAddress,
        Result.PASS,
        true
      )
    })

    test(`Security Issue when IPv4 wildcard address and port ${fromPort}`, async () => {
      await test84Rule(fromPort, toPort, ipV4WildcardAddress, Result.FAIL)
    })

    test(`Security Issue when IPv6 wildcard address and port ${fromPort}`, async () => {
      await test84Rule(fromPort, toPort, ipV6WildcardAddress, Result.FAIL)
    })

    test(`Security Issue when IPv4 wildcard address and port ${fromPort} (multiple values)`, async () => {
      await test84Rule(
        fromPort,
        toPort,
        ipV4WildcardAddress,
        Result.FAIL,
        true
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and no port range is specified', async () => {
      await test84Rule(
        undefined,
        undefined,
        ipV4WildcardAddress,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and no port range is specified', async () => {
      await test84Rule(
        undefined,
        undefined,
        ipV6WildcardAddress,
        Result.FAIL
      )
    })

    test(`Security Issue when there is an inbound rule with IPv4 wildcard address and port range includes the port ${fromPort}`, async () => {
      await test84Rule(0, fromPort + 100, ipV4WildcardAddress, Result.FAIL)
    })

    test(`Security Issue when there is an inbound rule with IPv6 wildcard address and port range includes the port ${fromPort}`, async () => {
      await test84Rule(0, fromPort + 100, ipV6WildcardAddress, Result.FAIL)
    })

    test('No Security Issue when there is an inbound rule with security group as source', async () => {
      await test84Rule(undefined, undefined, 'sg-049c76f349f62e4eb', Result.PASS)
    })
  })

  describe('AWS NIST 8.5 VPC security group inbound rules should not permit ingress from ‘0.0.0.0/0’ to all ports and protocols', () => {
    const rule = Aws_NIST_800_53_85 as Rule

    test('No Security Issue when there is an inbound rule with a random IPv4 address and all ports range', async () => {
      await testRule(0, 65535, '10.10.10.10/16', rule, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wildcard address and a port range not allow all ports', async () => {
      await testRule(1000, 2000, ipV4WildcardAddress, rule, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not allow all ports', async () => {
      await testRule(1000, 2000, ipV6WildcardAddress, rule, Result.PASS)
    })

    test('Security Issue when IPv4 wildcard address and allow all ports', async () => {
      await testRule(0, 65535, ipV4WildcardAddress, rule, Result.FAIL)
    })

    test('Security Issue when IPv6 wildcard address and allow all ports', async () => {
      await testRule(0, 65535, ipV6WildcardAddress, rule, Result.FAIL)
    })

    test('Security Issue when IPv4 wildcard address and allow all ports (multiple values)', async () => {
      await testRule(0, 65535, ipV4WildcardAddress, rule, Result.FAIL, true)
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and no port range is specified', async () => {
      await testRule(
        null,
        null,
        ipV4WildcardAddress,
        rule,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and no port range is specified', async () => {
      await testRule(
        null,
        null,
        ipV6WildcardAddress,
        rule,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and port range allow all ports', async () => {
      await testRule(0, 65535, ipV4WildcardAddress, rule, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and port range allow all ports', async () => {
      await testRule(0, 65535, ipV6WildcardAddress, rule, Result.FAIL)
    })

    test('No Security Issue when there is an inbound rule with security group as source', async () => {
      await testRule(null, null, 'sg-049c76f349f62e4eb', rule, Result.PASS)
    })
  })

  describe('AWS NIST 8.6 VPC security group inbound rules should not permit ingress from a public address to all ports and protocols', () => {
    const rule = Aws_NIST_800_53_86 as Rule

    test('No Security Issue when there is an inbound rule with a random IPv4 CIDR block and not allows all ports range', async () => {
      await testRule(1000, 2000, '10.10.10.10/16', rule, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule that allows all ports range with a private CIDR block', async () => {
      await testRule(0, 65535, '10.0.0.0/8', rule, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a random IPv4 CIDR block and allows all ports range', async () => {
      await testRule(0, 65535, '10.10.10.10/16', rule, Result.FAIL)
    })

    test('No Security Issue when there is an inbound rule with security group as source', async () => {
      await testRule(null, null, 'sg-049c76f349f62e4eb', rule, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with security group as source', async () => {
      await testRule(null, null, 'sg-049c76f349f62e4eb', rule, Result.PASS)
    })
  })

  describe('AWS NIST 8.7 VPC security group inbound rules should not permit ingress from any address to all ports and protocols', () => {
    const rule = Aws_NIST_800_53_87 as Rule

    test('No Security Issue when there is an inbound rule with IPv4 wildcard address and not allows all ports range', async () => {
      await testRule(1000, 2000, ipV4WildcardAddress, rule, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and not allows all ports range', async () => {
      await testRule(3000, 4000, ipV6WildcardAddress, rule, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 CIDR block and not allows all ports range', async () => {
      await testRule(0, 100, '10.10.10.10/16', rule, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and allows all ports range', async () => {
      await testRule(0, 65535, ipV4WildcardAddress, rule, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and allows all ports range', async () => {
      await testRule(0, 65535, ipV6WildcardAddress, rule, Result.FAIL)
    })

    test('No Security Issue when there is an inbound rule with security group as source', async () => {
      await testRule(null, null, 'sg-049c76f349f62e4eb', rule, Result.PASS)
    })
  })

  describe('AWS NIST 8.8 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ except to ports 80 and 443', () => {
    const rule = Aws_NIST_800_53_88 as Rule

    test('No Security Issue when there is an inbound rule with IPv4 wildcard address and port 80', async () => {
      await testRule(80, 80, ipV4WildcardAddress, rule, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and port 80', async () => {
      await testRule(80, 80, ipV6WildcardAddress, rule, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wildcard address and port 443', async () => {
      await testRule(443, 443, ipV4WildcardAddress, rule, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and port 443', async () => {
      await testRule(443, 443, ipV6WildcardAddress, rule, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and port different to 80 and 443', async () => {
      await testRule(132, 132, ipV4WildcardAddress, rule, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and port different to 80 and 443', async () => {
      await testRule(3389, 3389, ipV6WildcardAddress, rule, Result.FAIL)
    })

    test('No Security Issue when there is an inbound rule with security group as source', async () => {
      await testRule(null, null, 'sg-049c76f349f62e4eb', rule, Result.PASS)
    })
  })

  describe('AWS NIST 8.9 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to port 3389 (Remote Desktop Protocol)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_89 as Rule, 3389, 3389)
  })

  describe('AWS NIST 8.10 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 61621 (Cassandra OpsCenter Agent)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_810 as Rule, 61621, 61621)
  })

  describe('AWS NIST 8.11 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 636 (LDAP SSL)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_811 as Rule, 636, 636)
  })

  describe('AWS NIST 8.12 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 7001 (Cassandra)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_812 as Rule, 7001, 7001)
  })

  describe('AWS NIST 8.13 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 11214 (Memcached SSL)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_813 as Rule, 11214, 11214)
  })

  describe('AWS NIST 8.14 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 11215 (Memcached SSL)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_814 as Rule, 11215, 11215)
  })

  describe('AWS NIST 8.15 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 135 (MSSQL Debugger)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_815 as Rule, 135, 135)
  })

  describe('AWS NIST 8.16 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 137 (NetBIOS Name Service)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_816 as Rule, 137, 137)
  })

  describe('AWS NIST 8.17 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 138 (NetBios Datagram Service)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_817 as Rule, 138, 138)
  })

  describe('AWS NIST 8.18 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 139 (NetBios Session Service)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_818 as Rule, 139, 139)
  })

  describe('AWS NIST 8.19 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 1433 (MSSQL Server)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_819 as Rule, 1433, 1433)
  })

  describe('AWS NIST 8.20 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 1434 (MSSQL Admin)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_820 as Rule, 1434, 1434)
  })

  describe('AWS NIST 8.21 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to port 22 (SSH)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_821 as Rule, 22, 22)
  })

  describe('AWS NIST 8.22 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 23 (Telnet)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_822 as Rule, 23, 23)
  })

  describe('AWS NIST 8.23 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 2379 (etcd)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_823 as Rule, 2379, 2379)
  })

  describe('AWS NIST 8.24 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 2382 (SQL Server Analysis Services browser)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_824 as Rule, 2382, 2382)
  })

  describe('AWS NIST 8.25 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 2383 (SQL Server Analysis Services)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_825 as Rule, 2383, 2383)
  })

  describe('AWS NIST 8.26 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 2484 (Oracle DB SSL)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_826 as Rule, 2484, 2484)
  })

  describe('AWS NIST 8.27 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 27017 (MongoDB)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_827 as Rule, 27017, 27017)
  })

  describe('AWS NIST 8.28 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 27018 (MongoDB)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_828 as Rule, 27018, 27018)
  })

  describe('AWS NIST 8.29 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 27019 (MongoDB)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_829 as Rule, 27019, 27019)
  })

  describe('AWS NIST 8.30 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 3000 (Ruby on Rails web server)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_830 as Rule, 3000, 3000)
  })

  describe('AWS NIST 8.31 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 3020 (CIFS / SMB)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_831 as Rule, 3020, 3020)
  })

  describe('AWS NIST 8.32 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 3306 (MySQL)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_832 as Rule, 3306, 3306)
  })

  describe('AWS NIST 8.33 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 4505 (SaltStack Master)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_833 as Rule, 4505, 4505)
  })

  describe('AWS NIST 8.34 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 4506 (SaltStack Master)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_834 as Rule, 4506, 4506)
  })

  describe('AWS NIST 8.35 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 5432 (PostgreSQL)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_835 as Rule, 5432, 5432)
  })

  describe('AWS NIST 8.36 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 5500 (Virtual Network Computing)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_836 as Rule, 5500, 5500)
  })

  describe('AWS NIST 8.37 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 5800 (Virtual Network Computing), unless from ELBs', () => {
    testSecurityGroupRule(Aws_NIST_800_53_837 as Rule, 5800, 5800)
  })

  describe('AWS NIST 8.38 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 5900 (Virtual Network Computing)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_838 as Rule, 5900, 5900)
  })

  describe('AWS NIST 8.39 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 80 (HTTP), unless from ELBs', () => {
    const rule = Aws_NIST_800_53_839 as Rule
    const fromPort = 80
    const toPort = 80

    test(`No Security Issue when there is an inbound rule with a random IPv4 address and port ${fromPort}`, async () => {
      await testRule(fromPort, toPort, '10.10.10.10/16', rule, Result.PASS)
    })

    test(`No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port ${fromPort}`, async () => {
      await testRule(
        fromPort + 100,
        fromPort + 200,
        '10.10.10.10/16',
        rule,
        Result.PASS
      )
    })

    test(`No Security Issue when there is an inbound rule with IPv4 wildcard address and a port range not including the port ${fromPort}`, async () => {
      await testRule(
        fromPort + 100,
        fromPort + 200,
        ipV4WildcardAddress,
        rule,
        Result.PASS
      )
    })

    test(`No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not including the port ${fromPort}`, async () => {
      await testRule(
        fromPort + 100,
        fromPort + 200,
        ipV6WildcardAddress,
        rule,
        Result.PASS
      )
    })

    test(`No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not including the port ${fromPort} (multiple values)`, async () => {
      await testRule(
        fromPort + 100,
        fromPort + 200,
        ipV6WildcardAddress,
        rule,
        Result.PASS,
        true
      )
    })

    test(`Security Issue when IPv4 wildcard address and port ${fromPort}`, async () => {
      await testRule(fromPort, toPort, ipV4WildcardAddress, rule, Result.FAIL)
    })

    test(`Security Issue when IPv6 wildcard address and port ${fromPort}`, async () => {
      await testRule(fromPort, toPort, ipV6WildcardAddress, rule, Result.FAIL)
    })

    test(`Security Issue when IPv4 wildcard address and port ${fromPort} (multiple values)`, async () => {
      await testRule(
        fromPort,
        toPort,
        ipV4WildcardAddress,
        rule,
        Result.FAIL,
        true
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and no port range is specified', async () => {
      await testRule(
        null,
        null,
        ipV4WildcardAddress,
        rule,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and no port range is specified', async () => {
      await testRule(
        null,
        null,
        ipV6WildcardAddress,
        rule,
        Result.FAIL
      )
    })

    test(`Security Issue when there is an inbound rule with IPv4 wildcard address and port range includes the port ${fromPort}`, async () => {
      await testRule(0, fromPort + 100, ipV4WildcardAddress, rule, Result.FAIL)
    })

    test(`Security Issue when there is an inbound rule with IPv6 wildcard address and port range includes the port ${fromPort}`, async () => {
      await testRule(0, fromPort + 100, ipV6WildcardAddress, rule, Result.FAIL)
    })

    test('No Security Issue when there is an inbound rule with security group as source', async () => {
      await testRule(null, null, 'sg-049c76f349f62e4eb', rule, Result.PASS)
    })
  })

  describe('AWS NIST 8.40 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 8000 (HTTP Alternate)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_840 as Rule, 8000, 8000)
  })

  describe('AWS NIST 8.41 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 9200 (Elasticsearch)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_841 as Rule, 9200, 9200)
  })

  describe('AWS NIST 8.42 VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 9300 (Elasticsearch)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_842 as Rule, 9300, 9300)
  })

  describe('AWS NIST 8.43 VPC security groups attached to EC2 instances should not permit ingress from ‘0.0.0.0/0’ to all ports', () => {
    const test843Rule = async (
      fromPort: number | null,
      toPort: number | null,
      sourceAddress: string,
      expectedResult: Result,
      includeRandomValidData = false
    ): Promise<void> => {
      // Arrange
      const validInboundRule = {
        toPort: 123,
        fromPort: 456,
        source: '10.10.10.10/16',
      }
  
      const data: NIS8xQueryResponse = {
        queryawsEc2: [
          {
            id: cuid(),
            securityGroups: [
              {
                id: cuid(),
                inboundRules: [
                  {
                    fromPort,
                    toPort,
                    source: sourceAddress,
                  }
                ]
              },
            ],
          }
        ],
      }
  
      if (includeRandomValidData) {
        data.queryawsEc2?.[0].securityGroups?.[0].inboundRules?.push(validInboundRule)
        data.queryawsEc2?.[0].securityGroups?.push({
          id: cuid(),
          inboundRules: [validInboundRule, validInboundRule],
        })
      }
  
      // Act
      const [processedRule] = await rulesEngine.processRule(Aws_NIST_800_53_843 as Rule, { ...data })
  
      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a random IPv4 address and all ports range', async () => {
      await test843Rule(0, 65535, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wildcard address and a port range not allow all ports', async () => {
      await test843Rule(1000, 2000, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not allow all ports', async () => {
      await test843Rule(1000, 2000, ipV6WildcardAddress, Result.PASS)
    })

    test('Security Issue when IPv4 wildcard address and allow all ports', async () => {
      await test843Rule(0, 65535, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv6 wildcard address and allow all ports', async () => {
      await test843Rule(0, 65535, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv4 wildcard address and allow all ports (multiple values)', async () => {
      await test843Rule(0, 65535, ipV4WildcardAddress, Result.FAIL, true)
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and no port range is specified', async () => {
      await test843Rule(
        null,
        null,
        ipV4WildcardAddress,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and no port range is specified', async () => {
      await test843Rule(
        null,
        null,
        ipV6WildcardAddress,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and port range allow all ports', async () => {
      await test843Rule(0, 65535, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and port range allow all ports', async () => {
      await test843Rule(0, 65535, ipV6WildcardAddress, Result.FAIL)
    })

    test('No Security Issue when there is an inbound rule with security group as source', async () => {
      await test843Rule(null, null, 'sg-049c76f349f62e4eb', Result.PASS)
    })
  })

  describe('AWS NIST 8.44 VPC security groups attached to EC2 instances should not permit ingress from ‘0.0.0.0/0’ to TCP port 389 (LDAP)', () => {
    testSecurityGroupRule(Aws_NIST_800_53_844 as Rule, 389, 389)
  })

  describe('AWS NIST 8.45 VPC security groups attached to RDS instances should not permit ingress from ‘0.0.0.0/0’ to all ports', () => {
    const test845Rule = async (
      fromPort: number | null,
      toPort: number | null,
      sourceAddress: string,
      expectedResult: Result,
      includeRandomValidData = false
    ): Promise<void> => {
      // Arrange
      const validInboundRule = {
        toPort: 123,
        fromPort: 456,
        source: '10.10.10.10/16',
      }
  
      const data: NIS8xQueryResponse = {
        queryawsRdsDbInstance: [
          {
            id: cuid(),
            securityGroups: [
              {
                id: cuid(),
                inboundRules: [
                  {
                    fromPort,
                    toPort,
                    source: sourceAddress,
                  }
                ]
              },
            ],
          }
        ],
      }
  
      if (includeRandomValidData) {
        data.queryawsRdsDbInstance?.[0].securityGroups?.[0].inboundRules?.push(validInboundRule)
        data.queryawsRdsDbInstance?.[0].securityGroups?.push({
          id: cuid(),
          inboundRules: [validInboundRule, validInboundRule],
        })
      }
  
      // Act
      const [processedRule] = await rulesEngine.processRule(Aws_NIST_800_53_845 as Rule, { ...data })
  
      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a random IPv4 address and all ports range', async () => {
      await test845Rule(0, 65535, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wildcard address and a port range not allow all ports', async () => {
      await test845Rule(1000, 2000, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not allow all ports', async () => {
      await test845Rule(1000, 2000, ipV6WildcardAddress, Result.PASS)
    })

    test('Security Issue when IPv4 wildcard address and allow all ports', async () => {
      await test845Rule(0, 65535, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv6 wildcard address and allow all ports', async () => {
      await test845Rule(0, 65535, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv4 wildcard address and allow all ports (multiple values)', async () => {
      await test845Rule(0, 65535, ipV4WildcardAddress, Result.FAIL, true)
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and no port range is specified', async () => {
      await test845Rule(
        null,
        null,
        ipV4WildcardAddress,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and no port range is specified', async () => {
      await test845Rule(
        null,
        null,
        ipV6WildcardAddress,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and port range allow all ports', async () => {
      await test845Rule(0, 65535, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and port range allow all ports', async () => {
      await test845Rule(0, 65535, ipV6WildcardAddress, Result.FAIL)
    })

    test('No Security Issue when there is an inbound rule with security group as source', async () => {
      await test845Rule(null, null, 'sg-049c76f349f62e4eb', Result.PASS)
    })
  })
})
