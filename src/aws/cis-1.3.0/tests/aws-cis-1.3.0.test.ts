import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'


describe('CIS Amazon Web Services Foundations: 1.3.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'CIS',
    })
  })

  // TODO: Change once we have real checks
  describe("Dummy Check", () => {
    test('Dummy Test', async () => {
      expect('PASS').toBe(Result.PASS)
    })
  })
})
