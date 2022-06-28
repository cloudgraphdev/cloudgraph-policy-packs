import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_DNS_1 from '../rules/pci-dss-3.2.1-dns-check-1'
import Gcp_PCI_DSS_321_DNS_2 from '../rules/pci-dss-3.2.1-dns-check-2'
import Gcp_PCI_DSS_321_DNS_3 from '../rules/pci-dss-3.2.1-dns-check-3'

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

export interface CISDNSQueryResponse {
  querygcpDnsManagedZone?: QuerygcpDnsManagedZone[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'gcp',
      entityName: 'PCI',
    })
  })

  describe('DNS Check 1: Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC', () => {
    const testDNS1Rule = async (
      visibility: string,
      keyType: string,
      algorithm: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CISDNSQueryResponse = {
        querygcpDnsManagedZone: [
          {
            id: cuid(),
            visibility,
            dnssecConfigDefaultKeySpecs: [
              {
                keyType: 'keySigning',
                algorithm: 'rsasha512',
              },
              {
                keyType: 'keyTest',
                algorithm: 'rsasha1',
              },
              {
                keyType,
                algorithm,
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_DNS_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with visibility public and keyType keySigning and algorithm type different to rsasha1', async () => {
      await testDNS1Rule('public', 'keySigning', 'rsasha256', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with visibility private and keyType keySigning and algorithm type rsasha1', async () => {
      await testDNS1Rule('private', 'keySigning', 'rsasha256', Result.PASS)
    })

    test('Security Issue when there is an inbound rule with visibility public and keyType keySigning and algorithm type rsasha1', async () => {
      await testDNS1Rule('public', 'keySigning', 'rsasha1', Result.FAIL)
    })
  })

  describe('DNS Check 2: Ensure that DNSSEC is enabled for Cloud DNS', () => {
    const testDNS2Rule = async (
      visibility: string,
      dnssecConfigState: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CISDNSQueryResponse = {
        querygcpDnsManagedZone: [
          {
            id: cuid(),
            visibility,
            dnssecConfigState,
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_DNS_2 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with visibility public and dnssecConfigState is enabled', async () => {
      await testDNS2Rule('public', 'on', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with visibility private and dnssecConfigState is not enabled', async () => {
      await testDNS2Rule('private', 'off', Result.PASS)
    })

    test('Security Issue when there is an inbound rule with visibility public and dnssecConfigState is not enabled', async () => {
      await testDNS2Rule('public', 'off', Result.FAIL)
    })
  })

  describe('DNS Check 3: Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC', () => {
    const testDNS3Rule = async (
      visibility: string,
      keyType: string,
      algorithm: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CISDNSQueryResponse = {
        querygcpDnsManagedZone: [
          {
            id: cuid(),
            visibility,
            dnssecConfigDefaultKeySpecs: [
              {
                keyType: 'zoneSigning',
                algorithm: 'rsasha512',
              },
              {
                keyType: 'keyTest',
                algorithm: 'rsasha1',
              },
              {
                keyType,
                algorithm,
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_DNS_3 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with visibility public and keyType zoneSigning and algorithm type different to rsasha1', async () => {
      await testDNS3Rule('public', 'zoneSigning', 'rsasha256', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with visibility private and keyType zoneSigning and algorithm type rsasha1', async () => {
      await testDNS3Rule('private', 'zoneSigning', 'rsasha256', Result.PASS)
    })

    test('Security Issue when there is an inbound rule with visibility public and keyType zoneSigning and algorithm type rsasha1', async () => {
      await testDNS3Rule('public', 'zoneSigning', 'rsasha1', Result.FAIL)
    })
  })

})
