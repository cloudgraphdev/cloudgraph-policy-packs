/* eslint-disable max-len */
import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_PCI_DSS_321_Networking_1 from '../rules/pci-dss-3.2.1-networking-check-1'
import Gcp_PCI_DSS_321_Networking_2 from '../rules/pci-dss-3.2.1-networking-check-2'
import Gcp_PCI_DSS_321_Networking_3 from '../rules/pci-dss-3.2.1-networking-check-3'
import Gcp_PCI_DSS_321_Networking_4 from '../rules/pci-dss-3.2.1-networking-check-4'
import { initRuleEngine } from '../../../utils/test'

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

export interface GcpNetworkSubnet {
  purpose: string
  enableFlowLogs: boolean | null
}

export interface QuerygcpNetwork {
  id: string
  subnets?: GcpNetworkSubnet[]
  name?: string
  ipV4Range?: string | null
}

export interface DnssecConfigDefaultKeySpecs {
  keyType: string
  algorithm: string
}

export interface QuerygcpDnsManagedZone {
  id: string
  visibility?: string
  dnssecConfigState?: string
  dnssecConfigDefaultKeySpecs?: DnssecConfigDefaultKeySpecs[]
}

export interface SslPolicy {
  profile: string
  enabledFeatures?: string[]
  minTlsVersion: string
}

export interface TargetHttpsProxy {
  sslPolicy?: SslPolicy[]
}

export interface TargetSslProxy {
  sslPolicy?: SslPolicy[]
}

export interface QuerygcpTargetSslProxy {
  id: string
  sslPolicy?: SslPolicy[]
}
export interface QuerygcpTargetHttpsProxy {
  id: string
  sslPolicy?: SslPolicy[]
}

export interface PCIQueryResponse {
  querygcpFirewall?: QuerygcpFirewall[]
  querygcpNetwork?: QuerygcpNetwork[]
  querygcpTargetSslProxy?: QuerygcpTargetSslProxy[]
  querygcpTargetHttpsProxy?: QuerygcpTargetHttpsProxy[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('gcp', 'PCI')
  })

  describe('Networking check 1: Network firewall rules should not permit ingress from 0.0.0.0/0 to port 22 (SSH)', () => {
    const testRule = async (
      fromPort: number | undefined,
      toPort: number | undefined,
      sourceAddress: string,
      expectedResult: Result,
      protocol?: string
    ): Promise<void> => {
      // Arrange
      const data: PCIQueryResponse = {
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
        Gcp_PCI_DSS_321_Networking_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a random IPv4 address and port 22', async () => {
      await testRule(22, 22, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and port 80', async () => {
      await testRule(80, 80, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and port 80', async () => {
      await testRule(80, 80, ipV6WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port 22', async () => {
      await testRule(1000, 2000, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and a port range not including the port 22', async () => {
      await testRule(1000, 2000, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and a port range not including the port 22', async () => {
      await testRule(1000, 2000, ipV6WildcardAddress, Result.PASS)
    })

    test('Security Issue when IPv4 wilcard address and port 22 and tcp protocol', async () => {
      await testRule(22, 22, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv4 wilcard address and port 22 and all protocol', async () => {
      await testRule(22, 22, ipV4WildcardAddress, Result.FAIL, 'all')
    })

    test('Security Issue when IPv6 wilcard address and port 22 and tcp protocol', async () => {
      await testRule(22, 22, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv6 wilcard address and port 22 and all protocol', async () => {
      await testRule(22, 22, ipV6WildcardAddress, Result.FAIL, 'all')
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and no port range is specified', async () => {
      await testRule(undefined, undefined, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and no port range is specified', async () => {
      await testRule(undefined, undefined, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and port range includes the port 22', async () => {
      await testRule(0, 1000, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and port range includes the port 22', async () => {
      await testRule(0, 1000, ipV6WildcardAddress, Result.FAIL)
    })
  })

  describe('Networking check 2: Network firewall rules should not permit ingress from 0.0.0.0/0 to port 3389 (RDP)', () => {
    const testRule = async (
      fromPort: number | undefined,
      toPort: number | undefined,
      sourceAddress: string,
      expectedResult: Result,
      protocol?: string
    ): Promise<void> => {
      // Arrange
      const data: PCIQueryResponse = {
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
        Gcp_PCI_DSS_321_Networking_2 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a random IPv4 address and port 3389', async () => {
      await testRule(3389, 3389, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and port 80', async () => {
      await testRule(80, 80, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and port 80', async () => {
      await testRule(80, 80, ipV6WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port 3389', async () => {
      await testRule(1000, 2000, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and a port range not including the port 3389', async () => {
      await testRule(1000, 2000, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and a port range not including the port 3389', async () => {
      await testRule(1000, 2000, ipV6WildcardAddress, Result.PASS)
    })

    test('Security Issue when IPv4 wilcard address and port 3389 and tcp protocol', async () => {
      await testRule(3389, 3389, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv4 wilcard address and port 3389 and all protocol', async () => {
      await testRule(3389, 3389, ipV4WildcardAddress, Result.FAIL, 'all')
    })

    test('Security Issue when IPv6 wilcard address and port 3389 and tcp protocol', async () => {
      await testRule(3389, 3389, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv6 wilcard address and port 3389 and all protocol', async () => {
      await testRule(3389, 3389, ipV6WildcardAddress, Result.FAIL, 'all')
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and no port range is specified', async () => {
      await testRule(undefined, undefined, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and no port range is specified', async () => {
      await testRule(undefined, undefined, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and port range includes the port 3389', async () => {
      await testRule(0, 4000, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and port range includes the port 3389', async () => {
      await testRule(0, 4000, ipV6WildcardAddress, Result.FAIL)
    })
  })

  describe('Networking check 3: The default network for a project should be deleted', () => {
    const testRule = async (
      networkName: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: PCIQueryResponse = {
        querygcpNetwork: [
          {
            id: cuid(),
            name: networkName,
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_Networking_3 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a network name that is not equal to default', async () => {
      await testRule('test-network', Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a network name that is equal to default', async () => {
      await testRule('default', Result.FAIL)
    })
  })

  describe('Networking check 4: Load balancer HTTPS or SSL proxy SSL policies should not have weak cipher suites', () => {
    const getTestRuleAFixture = (): PCIQueryResponse => {
      return {
        querygcpTargetHttpsProxy: [
          {
            id: cuid(),
            sslPolicy: [
              {
                profile: 'MODERN',
                minTlsVersion: 'TLS_1_2',
              },
            ],
          },
        ],
      }
    }

    const getTestRuleBFixture = (): PCIQueryResponse => {
      return {
        querygcpTargetSslProxy: [
          {
            id: cuid(),
            sslPolicy: [
              {
                profile: 'MODERN',
                minTlsVersion: 'TLS_1_2',
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result,
      rule?: Rule
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(rule as Rule, {
        ...data,
      })

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    describe('querygcpTargetHttpsProxy query:', () => {
      let targetHttpsProxyRule: Rule
      beforeAll(() => {
        const { queries, ...ruleMetadata } = Gcp_PCI_DSS_321_Networking_4
        const query = queries.shift()
        targetHttpsProxyRule = {
          ...ruleMetadata,
          ...query,
        } as Rule
      })

      test('No Security Issue when proxies and ssl policies are secure', async () => {
        const data: PCIQueryResponse = getTestRuleAFixture()
        await testRule(data, Result.PASS, targetHttpsProxyRule)
      })

      test('Security Issue when proxies not have ssl policy', async () => {
        const data: PCIQueryResponse = getTestRuleAFixture()
        const targetHttpsProxy = data
          .querygcpTargetHttpsProxy?.[0] as QuerygcpTargetHttpsProxy
        targetHttpsProxy.sslPolicy = []
        await testRule(data, Result.FAIL, targetHttpsProxyRule)
      })

      test('Security Issue when HTTPS-PROXY with MODERN ssl policy and VERSION is NOT TLS_1_2', async () => {
        const data: PCIQueryResponse = getTestRuleAFixture()
        const targetHttpsProxy = data
          .querygcpTargetHttpsProxy?.[0] as QuerygcpTargetHttpsProxy
        targetHttpsProxy.sslPolicy = targetHttpsProxy.sslPolicy?.map(
          ({ minTlsVersion, ...p }) => {
            return {
              ...p,
              minTlsVersion: 'dummy',
            }
          }
        )
        await testRule(data, Result.FAIL, targetHttpsProxyRule)
      })

      test('Security Issue when HTTPS-PROXY with CUSTOM ssl policy and enabledFeatures contains invalid values', async () => {
        const invalidEnabledFeatureValues = [
          'TLS_RSA_WITH_AES_128_GCM_SHA256',
          'TLS_RSA_WITH_AES_256_GCM_SHA384',
          'TLS_RSA_WITH_AES_128_CBC_SHA',
          'TLS_RSA_WITH_AES_256_CBC_SHA',
          'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        ]
        for (const invalidEnabledFeatureValue of invalidEnabledFeatureValues) {
          const data: PCIQueryResponse = getTestRuleAFixture()
          const targetHttpsProxy = data
            .querygcpTargetHttpsProxy?.[0] as QuerygcpTargetHttpsProxy
          targetHttpsProxy.sslPolicy = targetHttpsProxy.sslPolicy?.map(
            ({ enabledFeatures, profile, ...p }) => {
              return {
                ...p,
                profile: 'CUSTOM',
                enabledFeatures: [invalidEnabledFeatureValue],
              }
            }
          )
          await testRule(data, Result.FAIL, targetHttpsProxyRule)
        }
      })
    })

    describe('querygcpTargetSslProxy query:', () => {
      let targetSslProxyRule: Rule
      beforeAll(() => {
        const { queries, ...ruleMetadata } = Gcp_PCI_DSS_321_Networking_4
        const query = queries.shift()
        targetSslProxyRule = {
          ...ruleMetadata,
          ...query,
        } as Rule
      })

      test('No Security Issue when proxies and ssl policies are secure', async () => {
        const data: PCIQueryResponse = getTestRuleBFixture()
        await testRule(data, Result.PASS, targetSslProxyRule)
      })

      test('Security Issue when proxies not have ssl policy', async () => {
        const data: PCIQueryResponse = getTestRuleBFixture()
        const targetSslProxy = data
          .querygcpTargetSslProxy?.[0] as QuerygcpTargetHttpsProxy
        targetSslProxy.sslPolicy = []
        await testRule(data, Result.FAIL, targetSslProxyRule)
      })

      test('Security Issue when HTTPS-PROXY with MODERN ssl policy and VERSION is NOT TLS_1_2', async () => {
        const data: PCIQueryResponse = getTestRuleBFixture()
        const targetSslProxy = data
          .querygcpTargetSslProxy?.[0] as QuerygcpTargetHttpsProxy
        targetSslProxy.sslPolicy = targetSslProxy.sslPolicy?.map(
          ({ minTlsVersion, ...p }) => {
            return {
              ...p,
              minTlsVersion: 'dummy',
            }
          }
        )
        await testRule(data, Result.FAIL, targetSslProxyRule)
      })

      test('Security Issue when HTTPS-PROXY with CUSTOM ssl policy and enabledFeatures contains invalid values', async () => {
        const invalidEnabledFeatureValues = [
          'TLS_RSA_WITH_AES_128_GCM_SHA256',
          'TLS_RSA_WITH_AES_256_GCM_SHA384',
          'TLS_RSA_WITH_AES_128_CBC_SHA',
          'TLS_RSA_WITH_AES_256_CBC_SHA',
          'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        ]
        for (const invalidEnabledFeatureValue of invalidEnabledFeatureValues) {
          const data: PCIQueryResponse = getTestRuleBFixture()
          const targetSslProxy = data
            .querygcpTargetSslProxy?.[0] as QuerygcpTargetHttpsProxy
          targetSslProxy.sslPolicy = targetSslProxy.sslPolicy?.map(
            ({ enabledFeatures, profile, ...p }) => {
              return {
                ...p,
                profile: 'CUSTOM',
                enabledFeatures: [invalidEnabledFeatureValue],
              }
            }
          )
          await testRule(data, Result.FAIL, targetSslProxyRule)
        }
      })
    })
  })
})
