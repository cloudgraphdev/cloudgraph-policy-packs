/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_CIS_120_36 from '../rules/gcp-cis-1.2.0-3.6'
import Gcp_CIS_120_37 from '../rules/gcp-cis-1.2.0-3.7'

const ipV4WildcardAddress = '0.0.0.0/0'
const ipV6WildcardAddress = '::/0'

export interface Allowed {
  ipProtocol: string
  ports: string[]
}

export interface QuerygcpFirewall {
  id: string
  sourceRanges: string[]
  direction: string
  allowed?: Allowed[]
}
export interface CIS3xQueryResponse {
  querygcpFirewall: QuerygcpFirewall[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine('gcp', 'CIS')
  })
  describe('GCP CIS 3.6 Ensure that SSH access is restricted from the internet', () => {
    const test36Rule = async (
      fromPort: number | undefined,
      toPort: number | undefined,
      sourceAddress: string,
      expectedResult: Result,
      protocol?: string
    ): Promise<void> => {
      // Arrange
      const data: CIS3xQueryResponse = {
        querygcpFirewall: [
          {
            id: cuid(),
            sourceRanges: [sourceAddress],
            direction: 'INGRESS',
            allowed: [
              {
                ipProtocol: 'icmp',
                ports: [],
              },
              {
                ipProtocol: protocol || 'tcp',
                ports: fromPort && toPort ? [`${fromPort}-${toPort}`] : [],
              },
              {
                ipProtocol: 'udp',
                ports: ['0-65535'],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_36 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a random IPv4 address and port 22', async () => {
      await test36Rule(22, 22, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and port 80', async () => {
      await test36Rule(80, 80, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and port 80', async () => {
      await test36Rule(80, 80, ipV6WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port 22', async () => {
      await test36Rule(1000, 2000, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and a port range not including the port 22', async () => {
      await test36Rule(1000, 2000, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and a port range not including the port 22', async () => {
      await test36Rule(1000, 2000, ipV6WildcardAddress, Result.PASS)
    })

    test('Security Issue when IPv4 wilcard address and port 22 and tcp protocol', async () => {
      await test36Rule(22, 22, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv4 wilcard address and port 22 and all protocol', async () => {
      await test36Rule(22, 22, ipV4WildcardAddress, Result.FAIL, 'all')
    })

    test('Security Issue when IPv6 wilcard address and port 22 and tcp protocol', async () => {
      await test36Rule(22, 22, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv6 wilcard address and port 22 and all protocol', async () => {
      await test36Rule(22, 22, ipV6WildcardAddress, Result.FAIL, 'all')
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and no port range is specified', async () => {
      await test36Rule(undefined, undefined, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and no port range is specified', async () => {
      await test36Rule(undefined, undefined, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and port range includes the port 22', async () => {
      await test36Rule(0, 1000, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and port range includes the port 22', async () => {
      await test36Rule(0, 1000, ipV6WildcardAddress, Result.FAIL)
    })
  })

  describe('GCP CIS 3.7 Ensure that RDP access is restricted from the internet', () => {
    const test37Rule = async (
      fromPort: number | undefined,
      toPort: number | undefined,
      sourceAddress: string,
      expectedResult: Result,
      protocol?: string
    ): Promise<void> => {
      // Arrange
      const data: CIS3xQueryResponse = {
        querygcpFirewall: [
          {
            id: cuid(),
            sourceRanges: [sourceAddress],
            direction: 'INGRESS',
            allowed: [
              {
                ipProtocol: 'icmp',
                ports: [],
              },
              {
                ipProtocol: protocol || 'tcp',
                ports: fromPort && toPort ? [`${fromPort}-${toPort}`] : [],
              },
              {
                ipProtocol: 'udp',
                ports: ['0-65535'],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_37 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a random IPv4 address and port 3986', async () => {
      await test37Rule(3986, 3986, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and port 80', async () => {
      await test37Rule(80, 80, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and port 80', async () => {
      await test37Rule(80, 80, ipV6WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port 3986', async () => {
      await test37Rule(1000, 2000, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and a port range not including the port 3986', async () => {
      await test37Rule(1000, 2000, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and a port range not including the port 3986', async () => {
      await test37Rule(1000, 2000, ipV6WildcardAddress, Result.PASS)
    })

    test('Security Issue when IPv4 wilcard address and port 3986 and tcp protocol', async () => {
      await test37Rule(3986, 3986, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv4 wilcard address and port 3986 and all protocol', async () => {
      await test37Rule(3986, 3986, ipV4WildcardAddress, Result.FAIL, 'all')
    })

    test('Security Issue when IPv6 wilcard address and port 3986 and tcp protocol', async () => {
      await test37Rule(3986, 3986, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv6 wilcard address and port 3986 and all protocol', async () => {
      await test37Rule(3986, 3986, ipV6WildcardAddress, Result.FAIL, 'all')
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and no port range is specified', async () => {
      await test37Rule(undefined, undefined, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and no port range is specified', async () => {
      await test37Rule(undefined, undefined, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and port range includes the port 3986', async () => {
      await test37Rule(0, 4000, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and port range includes the port 3986', async () => {
      await test37Rule(0, 4000, ipV6WildcardAddress, Result.FAIL)
    })
  })
})
