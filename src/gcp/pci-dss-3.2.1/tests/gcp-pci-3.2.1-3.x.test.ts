import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_31 from '../rules/pci-dss-3.2.1-3.1'
import Gcp_PCI_DSS_321_32 from '../rules/pci-dss-3.2.1-3.2'
import Gcp_PCI_DSS_321_33 from '../rules/pci-dss-3.2.1-3.3'

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

export interface CIS3xQueryResponse {
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

  describe('GCP PCI 3.1 Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC', () => {
    const test31Rule = async (
      visibility: string,
      keyType: string,
      algorithm: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS3xQueryResponse = {
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
        Gcp_PCI_DSS_321_31 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with visibility public and keyType keySigning and algorithm type different to rsasha1', async () => {
      await test31Rule('public', 'keySigning', 'rsasha256', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with visibility private and keyType keySigning and algorithm type rsasha1', async () => {
      await test31Rule('private', 'keySigning', 'rsasha256', Result.PASS)
    })

    test('Security Issue when there is an inbound rule with visibility public and keyType keySigning and algorithm type rsasha1', async () => {
      await test31Rule('public', 'keySigning', 'rsasha1', Result.FAIL)
    })
  })

  describe('GCP PCI 3.2 Ensure that DNSSEC is enabled for Cloud DNS', () => {
    const test32Rule = async (
      visibility: string,
      dnssecConfigState: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS3xQueryResponse = {
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
        Gcp_PCI_DSS_321_32 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with visibility public and dnssecConfigState is enabled', async () => {
      await test32Rule('public', 'on', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with visibility private and dnssecConfigState is not enabled', async () => {
      await test32Rule('private', 'off', Result.PASS)
    })

    test('Security Issue when there is an inbound rule with visibility public and dnssecConfigState is not enabled', async () => {
      await test32Rule('public', 'off', Result.FAIL)
    })
  })

  describe('GCP PCI 3.3 Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC', () => {
    const test33Rule = async (
      visibility: string,
      keyType: string,
      algorithm: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS3xQueryResponse = {
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
        Gcp_PCI_DSS_321_33 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with visibility public and keyType zoneSigning and algorithm type different to rsasha1', async () => {
      await test33Rule('public', 'zoneSigning', 'rsasha256', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with visibility private and keyType zoneSigning and algorithm type rsasha1', async () => {
      await test33Rule('private', 'zoneSigning', 'rsasha256', Result.PASS)
    })

    test('Security Issue when there is an inbound rule with visibility public and keyType zoneSigning and algorithm type rsasha1', async () => {
      await test33Rule('public', 'zoneSigning', 'rsasha1', Result.FAIL)
    })
  })

})
