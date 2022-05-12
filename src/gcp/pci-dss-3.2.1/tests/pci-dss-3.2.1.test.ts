import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'gcp',
      entityName: 'PCI',
    })
  })

  // TODO: Change once we have real checks
  describe("Dummy Check", () => {
    test('Dummy Test', async () => {
      expect('PASS').toBe(Result.PASS)
    })
  })
})
