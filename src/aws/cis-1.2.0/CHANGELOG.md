## [0.14.1-alpha.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.14.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.14.1-alpha.1) (2023-05-17)


### Bug Fixes

* **checks:** Cannot read properties of undefined (reading 'direction') ([700a3de](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/700a3de4f5a7893aa9cba2238be485dc2254e7a6))

# [0.14.0](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.13.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.14.0) (2023-04-28)


### Bug Fixes

* **CG-1242:** fix aws cis 1.4.0, 1.16 rule ([0f6157f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/0f6157ff0a7cd0140ef7d0721f186f5f445338ff))
* **CG-1327:** fix AWS CIS 1.40 2.1.2 rule ([51a22e1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/51a22e1559eeedd566c138574fe75d1f02fa250c))
* **CG-1328:** fix the AWS CIS 1.4.0 2.1.5 rule ([2942785](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2942785d00b98351a24f4185eb7a3ace418a3c15))
* **CG-1329:** fix aws cis 1.4.0 rule 2.2.1 ([41457c4](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/41457c4916d521b0534bef6b3f9ba1ed8bb09883))
* **CG-1330:** AWS CIS 1.4.0 rule 3.8 fix ([d4f0421](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/d4f0421dc529652abe7cd89309664b63ef3ebe29))
* **CG-1331:** fix aws pci asg rule ([34f894f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/34f894f0f026c754914e5c063a4072c791a29637))
* **CG-1332:** fix aws pci ec2 check 1 ([71b45cf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/71b45cfab75d11a2db6c9cff6e5968af76fb480d))
* **CG-1335:** AWS PCI IAM 1 rule fix ([f6c9f40](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/f6c9f409beebf3240679cca678f5d0e18958f185))
* **CG-1336:** fix PCI IAM check 3 ([2188b34](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2188b3446200ef5646ac98eefaf73e5fd95615b2))
* **pnpm:** using semantic-release-pnpm ([eb9f3f2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/eb9f3f22e85375b79be205c62adc09aa60628343))
* **pnpm:** using semantic-release-pnpm ([41e9cca](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/41e9cca064a9f0e661f81f27c31f7d047df287de))
* **pnpmz:** using semantic-release-pnpm 1.0.2 ([a794f9e](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a794f9ec37c076fde5d660a49e8b313bc79236ea))
* **pnpmz:** using semantic-release-pnpm 1.0.2 ([6fec472](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/6fec472ecd10381f3b90f362f8c31519db9b0f53))
* **test:** fix duplicate import ([2bac2fd](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2bac2fd43d3248bad8a408cfcd8ce4b5bba75d18))


### Features

* **CG-1151:** support gcp nist IAM default audit log config check ([b821ecf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b821ecfe243ce1df874374834b39193d685ad623))
* **CG-1164:** add Activity Log Retention ([ec03e27](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ec03e276159daa8a57da018071e32b73d6aa91ab))
* **CG-1164:** add azure pci sql server auditing enabled check ([a9e34a7](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a9e34a717d8f864fa8c98a33ccb36a3420dd8098))
* **CG-1165:** add azure monitoring rule ([4383c3c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/4383c3ca29a5a85a52a206590f71545ee09d713b))
* **CG-1165:** add azure pci monitor log profile rule ([a72f81c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a72f81c49c4a30704d5ad641de290d52114282d8))
* **CG-1165:** rule name update ([4ca8eb7](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/4ca8eb7d53f6e99a9655ff7bb86eb889ab027115))
* **CG-1165:** update README ([11e2604](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/11e26043b301c0dfc7235552870d4f88b472a6a2))
* **CG-1168:** add azure networking 3 rule ([6d3925d](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/6d3925dfbd6c06e717a3ce650b594a8e6baa0df0))
* **CG-1169:** add azure user-check-1 rule ([2f1ef53](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2f1ef537624f30b644d8b4ca15881a052f3ee007))
* **CG-1173:** add azure WAF enabled check ([a6a8b31](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a6a8b31b40d4711e043ac2e717df2ee5491f1c5a))
* **CG-1174:** fix monitoring check 5 ([4b3c357](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/4b3c357096cc50d729b542b4204fb7c8a2bcf88c))
* **CG-1174:** support azure pci monitoring rules ([3b86f5c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3b86f5cd017409e11b5e4d5d1aa6867349f81a9b))
* **CG-1175:** add azure encryption transit rule check ([e6f01d4](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/e6f01d4bcf02d5d7f243ad96fec4302e75a58e9b))
* **CG-1176:** add network access rules and policies version check rules ([d4e1604](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/d4e16043affc4553d4fb56d05f908461ff439123))
* **CG-1176:** merge from alpha conflict resolved ([8be4624](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/8be4624d2479435dd774d73255ca5c2a26611466))
* **CG-1176:** README update ([bfde2ed](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/bfde2edced9fab3210c9a69a740a1659b9208bd1))
* **CG-1263:** update azure network watcher cis and nist rule ([af8853e](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/af8853e4f21338f1f6e80f9644550131372b89c6))
* **CG-1280:** add aws cis 1.5 iam rules ([9bac0ec](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/9bac0ec8ceb27ca2f77a85f4d11154f311a75b12))
* **CG-1281:** add aws cis 1.5 logging rules ([1bf5c08](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/1bf5c08273a5ea41f842ce9d8be48802a50a1bcf))
* **CG-1282:** add support monitoring rules ([46c9483](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/46c94833fae665b9ab12482a247ff5a63d03fc42))
* **CG-1283:** add AWS CIS 1.5.0 4.16 rule ([fe66eac](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/fe66eacf5dce85893bdcd3d6e256800ba9a70858))
* **CG-1283:** partial rule ([2b5c662](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2b5c66256478a6206f420b01a4af780d32bc30be))
* **CG-1284:** add networking rule support ([b758b72](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b758b72735948f823b131b30b82be3794b1d2215))
* **CG-1285:** add aws cis 150 5.3 ([6528999](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/65289997ec7a51f07b3a4392db7d487206418828))
* **CG-1286:** add storage rules support ([0934441](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/09344413a18f1f6289e1cd02f8d594983b5dde46))
* **CG-1287:** add aws cis 2.3.2 support ([e6ee33f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/e6ee33fec483681e6539df01a3aa89359073e11b))
* **CG-1288:** add aws cis 233 support ([81359bf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/81359bf30d66f3d849f1c6b8b3b6cd9ab1356842))
* **CG-1289:** add aws cis 1.5.0 2.4.1 ([998bf70](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/998bf7013e8c3acbc8633ced5e449464a6ee3d26))
* **CG-1290:** create boilerplate for aws cis 1.5.0 ([9c1d6f3](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/9c1d6f392a03b506424e74682caca85ff9188238))
* **CG-1291:** add gcp cis 130 boilerplate ([f7d6418](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/f7d6418826ba53ca588a552ad5a7b58300bfe468))
* **CG-1292:** add GCP CIS 1.3 rules similar to 1.2 ([ff12a3f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ff12a3fed175cfeed414c4bf3d727ad65699230d))
* **CG-1293:** add GCP CIS 1.30 1.16 rule ([286ea82](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/286ea828eaa472848613bd977663fd56002d1f78))
* **CG-1293:** update the rule checker ([3e992cf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3e992cf0d929c0e1e830e907e2ecc2a674cac77e))
* **CG-1294:** add GCP CIS 1.30 1.18 rule ([6cea799](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/6cea799e50f7f0237648f578982010cbc3d05387))
* **CG-1294:** fix title ([751a65a](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/751a65a830da19c7b2ae9af217df597b311e9131))
* **CG-1298:** add GCP CIS 1.30 2.13 ([cbe48df](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/cbe48dff0d0ea0769aa7c16aef9b81e9ddcf66d3))
* **CG-1298:** gql fix in the rule ([7799c95](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/7799c955dce9385e8cce19d1a3f6cfd9bcec2dc0))
* **CG-1298:** update uniot test ([33e5b42](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/33e5b429edbb4f49230d893c019f5ff4b6c59d81))
* **CG-1299:** add GCP CIS 1.30 2.14 rule ([2baa517](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2baa5174dd36e98d6e71cd3c5f8064e850c069bf))
* **CG-1300:** add gcp cis 1.30 2.15 ([fe76508](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/fe76508cfb7cbc5ce90b6cc6d51949e55c9a3117))
* **CG-1302:** add gcp cis 1.30 3.10 ([9f0fa54](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/9f0fa549a54fe9918746b006bb7ddbdf5e5b649a))
* **CG-1304:** add gcp cis 1.30 4.12 ([b718845](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b718845e0b66999852178afa53d31f6ba4e226d8))
* **CG-1306:** pushed wrong rule, fixed ([256cd5c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/256cd5cb89e1356508f9542e53127177328d8410))

# [0.14.0](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.13.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.14.0) (2023-04-28)


### Bug Fixes

* **CG-1242:** fix aws cis 1.4.0, 1.16 rule ([0f6157f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/0f6157ff0a7cd0140ef7d0721f186f5f445338ff))
* **CG-1327:** fix AWS CIS 1.40 2.1.2 rule ([51a22e1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/51a22e1559eeedd566c138574fe75d1f02fa250c))
* **CG-1328:** fix the AWS CIS 1.4.0 2.1.5 rule ([2942785](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2942785d00b98351a24f4185eb7a3ace418a3c15))
* **CG-1329:** fix aws cis 1.4.0 rule 2.2.1 ([41457c4](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/41457c4916d521b0534bef6b3f9ba1ed8bb09883))
* **CG-1330:** AWS CIS 1.4.0 rule 3.8 fix ([d4f0421](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/d4f0421dc529652abe7cd89309664b63ef3ebe29))
* **CG-1331:** fix aws pci asg rule ([34f894f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/34f894f0f026c754914e5c063a4072c791a29637))
* **CG-1332:** fix aws pci ec2 check 1 ([71b45cf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/71b45cfab75d11a2db6c9cff6e5968af76fb480d))
* **CG-1335:** AWS PCI IAM 1 rule fix ([f6c9f40](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/f6c9f409beebf3240679cca678f5d0e18958f185))
* **CG-1336:** fix PCI IAM check 3 ([2188b34](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2188b3446200ef5646ac98eefaf73e5fd95615b2))
* **pnpm:** using semantic-release-pnpm ([eb9f3f2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/eb9f3f22e85375b79be205c62adc09aa60628343))
* **pnpm:** using semantic-release-pnpm ([41e9cca](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/41e9cca064a9f0e661f81f27c31f7d047df287de))
* **pnpmz:** using semantic-release-pnpm 1.0.2 ([a794f9e](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a794f9ec37c076fde5d660a49e8b313bc79236ea))
* **pnpmz:** using semantic-release-pnpm 1.0.2 ([6fec472](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/6fec472ecd10381f3b90f362f8c31519db9b0f53))
* **test:** fix duplicate import ([2bac2fd](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2bac2fd43d3248bad8a408cfcd8ce4b5bba75d18))


### Features

* **CG-1151:** support gcp nist IAM default audit log config check ([b821ecf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b821ecfe243ce1df874374834b39193d685ad623))
* **CG-1164:** add Activity Log Retention ([ec03e27](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ec03e276159daa8a57da018071e32b73d6aa91ab))
* **CG-1164:** add azure pci sql server auditing enabled check ([a9e34a7](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a9e34a717d8f864fa8c98a33ccb36a3420dd8098))
* **CG-1165:** add azure monitoring rule ([4383c3c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/4383c3ca29a5a85a52a206590f71545ee09d713b))
* **CG-1165:** add azure pci monitor log profile rule ([a72f81c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a72f81c49c4a30704d5ad641de290d52114282d8))
* **CG-1165:** rule name update ([4ca8eb7](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/4ca8eb7d53f6e99a9655ff7bb86eb889ab027115))
* **CG-1165:** update README ([11e2604](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/11e26043b301c0dfc7235552870d4f88b472a6a2))
* **CG-1168:** add azure networking 3 rule ([6d3925d](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/6d3925dfbd6c06e717a3ce650b594a8e6baa0df0))
* **CG-1169:** add azure user-check-1 rule ([2f1ef53](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2f1ef537624f30b644d8b4ca15881a052f3ee007))
* **CG-1173:** add azure WAF enabled check ([a6a8b31](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a6a8b31b40d4711e043ac2e717df2ee5491f1c5a))
* **CG-1174:** fix monitoring check 5 ([4b3c357](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/4b3c357096cc50d729b542b4204fb7c8a2bcf88c))
* **CG-1174:** support azure pci monitoring rules ([3b86f5c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3b86f5cd017409e11b5e4d5d1aa6867349f81a9b))
* **CG-1175:** add azure encryption transit rule check ([e6f01d4](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/e6f01d4bcf02d5d7f243ad96fec4302e75a58e9b))
* **CG-1176:** add network access rules and policies version check rules ([d4e1604](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/d4e16043affc4553d4fb56d05f908461ff439123))
* **CG-1176:** merge from alpha conflict resolved ([8be4624](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/8be4624d2479435dd774d73255ca5c2a26611466))
* **CG-1176:** README update ([bfde2ed](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/bfde2edced9fab3210c9a69a740a1659b9208bd1))
* **CG-1263:** update azure network watcher cis and nist rule ([af8853e](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/af8853e4f21338f1f6e80f9644550131372b89c6))
* **CG-1280:** add aws cis 1.5 iam rules ([9bac0ec](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/9bac0ec8ceb27ca2f77a85f4d11154f311a75b12))
* **CG-1281:** add aws cis 1.5 logging rules ([1bf5c08](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/1bf5c08273a5ea41f842ce9d8be48802a50a1bcf))
* **CG-1282:** add support monitoring rules ([46c9483](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/46c94833fae665b9ab12482a247ff5a63d03fc42))
* **CG-1283:** add AWS CIS 1.5.0 4.16 rule ([fe66eac](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/fe66eacf5dce85893bdcd3d6e256800ba9a70858))
* **CG-1283:** partial rule ([2b5c662](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2b5c66256478a6206f420b01a4af780d32bc30be))
* **CG-1284:** add networking rule support ([b758b72](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b758b72735948f823b131b30b82be3794b1d2215))
* **CG-1285:** add aws cis 150 5.3 ([6528999](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/65289997ec7a51f07b3a4392db7d487206418828))
* **CG-1286:** add storage rules support ([0934441](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/09344413a18f1f6289e1cd02f8d594983b5dde46))
* **CG-1287:** add aws cis 2.3.2 support ([e6ee33f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/e6ee33fec483681e6539df01a3aa89359073e11b))
* **CG-1288:** add aws cis 233 support ([81359bf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/81359bf30d66f3d849f1c6b8b3b6cd9ab1356842))
* **CG-1289:** add aws cis 1.5.0 2.4.1 ([998bf70](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/998bf7013e8c3acbc8633ced5e449464a6ee3d26))
* **CG-1290:** create boilerplate for aws cis 1.5.0 ([9c1d6f3](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/9c1d6f392a03b506424e74682caca85ff9188238))
* **CG-1291:** add gcp cis 130 boilerplate ([f7d6418](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/f7d6418826ba53ca588a552ad5a7b58300bfe468))
* **CG-1292:** add GCP CIS 1.3 rules similar to 1.2 ([ff12a3f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ff12a3fed175cfeed414c4bf3d727ad65699230d))
* **CG-1293:** add GCP CIS 1.30 1.16 rule ([286ea82](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/286ea828eaa472848613bd977663fd56002d1f78))
* **CG-1293:** update the rule checker ([3e992cf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3e992cf0d929c0e1e830e907e2ecc2a674cac77e))
* **CG-1294:** add GCP CIS 1.30 1.18 rule ([6cea799](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/6cea799e50f7f0237648f578982010cbc3d05387))
* **CG-1294:** fix title ([751a65a](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/751a65a830da19c7b2ae9af217df597b311e9131))
* **CG-1298:** add GCP CIS 1.30 2.13 ([cbe48df](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/cbe48dff0d0ea0769aa7c16aef9b81e9ddcf66d3))
* **CG-1298:** gql fix in the rule ([7799c95](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/7799c955dce9385e8cce19d1a3f6cfd9bcec2dc0))
* **CG-1298:** update uniot test ([33e5b42](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/33e5b429edbb4f49230d893c019f5ff4b6c59d81))
* **CG-1299:** add GCP CIS 1.30 2.14 rule ([2baa517](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2baa5174dd36e98d6e71cd3c5f8064e850c069bf))
* **CG-1300:** add gcp cis 1.30 2.15 ([fe76508](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/fe76508cfb7cbc5ce90b6cc6d51949e55c9a3117))
* **CG-1302:** add gcp cis 1.30 3.10 ([9f0fa54](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/9f0fa549a54fe9918746b006bb7ddbdf5e5b649a))
* **CG-1304:** add gcp cis 1.30 4.12 ([b718845](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b718845e0b66999852178afa53d31f6ba4e226d8))
* **CG-1306:** pushed wrong rule, fixed ([256cd5c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/256cd5cb89e1356508f9542e53127177328d8410))

# [0.14.0](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.13.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.14.0) (2023-04-28)


### Bug Fixes

* **CG-1242:** fix aws cis 1.4.0, 1.16 rule ([0f6157f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/0f6157ff0a7cd0140ef7d0721f186f5f445338ff))
* **CG-1327:** fix AWS CIS 1.40 2.1.2 rule ([51a22e1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/51a22e1559eeedd566c138574fe75d1f02fa250c))
* **CG-1328:** fix the AWS CIS 1.4.0 2.1.5 rule ([2942785](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2942785d00b98351a24f4185eb7a3ace418a3c15))
* **CG-1329:** fix aws cis 1.4.0 rule 2.2.1 ([41457c4](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/41457c4916d521b0534bef6b3f9ba1ed8bb09883))
* **CG-1330:** AWS CIS 1.4.0 rule 3.8 fix ([d4f0421](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/d4f0421dc529652abe7cd89309664b63ef3ebe29))
* **CG-1331:** fix aws pci asg rule ([34f894f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/34f894f0f026c754914e5c063a4072c791a29637))
* **CG-1332:** fix aws pci ec2 check 1 ([71b45cf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/71b45cfab75d11a2db6c9cff6e5968af76fb480d))
* **CG-1335:** AWS PCI IAM 1 rule fix ([f6c9f40](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/f6c9f409beebf3240679cca678f5d0e18958f185))
* **CG-1336:** fix PCI IAM check 3 ([2188b34](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2188b3446200ef5646ac98eefaf73e5fd95615b2))
* **pnpm:** using semantic-release-pnpm ([eb9f3f2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/eb9f3f22e85375b79be205c62adc09aa60628343))
* **pnpm:** using semantic-release-pnpm ([41e9cca](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/41e9cca064a9f0e661f81f27c31f7d047df287de))
* **pnpmz:** using semantic-release-pnpm 1.0.2 ([a794f9e](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a794f9ec37c076fde5d660a49e8b313bc79236ea))
* **pnpmz:** using semantic-release-pnpm 1.0.2 ([6fec472](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/6fec472ecd10381f3b90f362f8c31519db9b0f53))
* **test:** fix duplicate import ([2bac2fd](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2bac2fd43d3248bad8a408cfcd8ce4b5bba75d18))


### Features

* **CG-1151:** support gcp nist IAM default audit log config check ([b821ecf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b821ecfe243ce1df874374834b39193d685ad623))
* **CG-1164:** add Activity Log Retention ([ec03e27](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ec03e276159daa8a57da018071e32b73d6aa91ab))
* **CG-1164:** add azure pci sql server auditing enabled check ([a9e34a7](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a9e34a717d8f864fa8c98a33ccb36a3420dd8098))
* **CG-1165:** add azure monitoring rule ([4383c3c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/4383c3ca29a5a85a52a206590f71545ee09d713b))
* **CG-1165:** add azure pci monitor log profile rule ([a72f81c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a72f81c49c4a30704d5ad641de290d52114282d8))
* **CG-1165:** rule name update ([4ca8eb7](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/4ca8eb7d53f6e99a9655ff7bb86eb889ab027115))
* **CG-1165:** update README ([11e2604](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/11e26043b301c0dfc7235552870d4f88b472a6a2))
* **CG-1168:** add azure networking 3 rule ([6d3925d](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/6d3925dfbd6c06e717a3ce650b594a8e6baa0df0))
* **CG-1169:** add azure user-check-1 rule ([2f1ef53](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2f1ef537624f30b644d8b4ca15881a052f3ee007))
* **CG-1173:** add azure WAF enabled check ([a6a8b31](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/a6a8b31b40d4711e043ac2e717df2ee5491f1c5a))
* **CG-1174:** fix monitoring check 5 ([4b3c357](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/4b3c357096cc50d729b542b4204fb7c8a2bcf88c))
* **CG-1174:** support azure pci monitoring rules ([3b86f5c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3b86f5cd017409e11b5e4d5d1aa6867349f81a9b))
* **CG-1175:** add azure encryption transit rule check ([e6f01d4](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/e6f01d4bcf02d5d7f243ad96fec4302e75a58e9b))
* **CG-1176:** add network access rules and policies version check rules ([d4e1604](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/d4e16043affc4553d4fb56d05f908461ff439123))
* **CG-1176:** merge from alpha conflict resolved ([8be4624](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/8be4624d2479435dd774d73255ca5c2a26611466))
* **CG-1176:** README update ([bfde2ed](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/bfde2edced9fab3210c9a69a740a1659b9208bd1))
* **CG-1263:** update azure network watcher cis and nist rule ([af8853e](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/af8853e4f21338f1f6e80f9644550131372b89c6))
* **CG-1280:** add aws cis 1.5 iam rules ([9bac0ec](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/9bac0ec8ceb27ca2f77a85f4d11154f311a75b12))
* **CG-1281:** add aws cis 1.5 logging rules ([1bf5c08](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/1bf5c08273a5ea41f842ce9d8be48802a50a1bcf))
* **CG-1282:** add support monitoring rules ([46c9483](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/46c94833fae665b9ab12482a247ff5a63d03fc42))
* **CG-1283:** add AWS CIS 1.5.0 4.16 rule ([fe66eac](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/fe66eacf5dce85893bdcd3d6e256800ba9a70858))
* **CG-1283:** partial rule ([2b5c662](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2b5c66256478a6206f420b01a4af780d32bc30be))
* **CG-1284:** add networking rule support ([b758b72](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b758b72735948f823b131b30b82be3794b1d2215))
* **CG-1285:** add aws cis 150 5.3 ([6528999](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/65289997ec7a51f07b3a4392db7d487206418828))
* **CG-1286:** add storage rules support ([0934441](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/09344413a18f1f6289e1cd02f8d594983b5dde46))
* **CG-1287:** add aws cis 2.3.2 support ([e6ee33f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/e6ee33fec483681e6539df01a3aa89359073e11b))
* **CG-1288:** add aws cis 233 support ([81359bf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/81359bf30d66f3d849f1c6b8b3b6cd9ab1356842))
* **CG-1289:** add aws cis 1.5.0 2.4.1 ([998bf70](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/998bf7013e8c3acbc8633ced5e449464a6ee3d26))
* **CG-1290:** create boilerplate for aws cis 1.5.0 ([9c1d6f3](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/9c1d6f392a03b506424e74682caca85ff9188238))
* **CG-1291:** add gcp cis 130 boilerplate ([f7d6418](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/f7d6418826ba53ca588a552ad5a7b58300bfe468))
* **CG-1292:** add GCP CIS 1.3 rules similar to 1.2 ([ff12a3f](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ff12a3fed175cfeed414c4bf3d727ad65699230d))
* **CG-1293:** add GCP CIS 1.30 1.16 rule ([286ea82](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/286ea828eaa472848613bd977663fd56002d1f78))
* **CG-1293:** update the rule checker ([3e992cf](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3e992cf0d929c0e1e830e907e2ecc2a674cac77e))
* **CG-1294:** add GCP CIS 1.30 1.18 rule ([6cea799](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/6cea799e50f7f0237648f578982010cbc3d05387))
* **CG-1294:** fix title ([751a65a](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/751a65a830da19c7b2ae9af217df597b311e9131))
* **CG-1298:** add GCP CIS 1.30 2.13 ([cbe48df](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/cbe48dff0d0ea0769aa7c16aef9b81e9ddcf66d3))
* **CG-1298:** gql fix in the rule ([7799c95](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/7799c955dce9385e8cce19d1a3f6cfd9bcec2dc0))
* **CG-1298:** update uniot test ([33e5b42](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/33e5b429edbb4f49230d893c019f5ff4b6c59d81))
* **CG-1299:** add GCP CIS 1.30 2.14 rule ([2baa517](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/2baa5174dd36e98d6e71cd3c5f8064e850c069bf))
* **CG-1300:** add gcp cis 1.30 2.15 ([fe76508](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/fe76508cfb7cbc5ce90b6cc6d51949e55c9a3117))
* **CG-1302:** add gcp cis 1.30 3.10 ([9f0fa54](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/9f0fa549a54fe9918746b006bb7ddbdf5e5b649a))
* **CG-1304:** add gcp cis 1.30 4.12 ([b718845](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b718845e0b66999852178afa53d31f6ba4e226d8))
* **CG-1306:** pushed wrong rule, fixed ([256cd5c](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/256cd5cb89e1356508f9542e53127177328d8410))

# [@cloudgraph/policy-pack-aws-cis-1.2.0-v0.13.1-alpha.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.13.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.13.1-alpha.1) (2022-12-14)


### Bug Fixes

* **pnpm:** using semantic-release-pnpm ([eb9f3f2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/eb9f3f22e85375b79be205c62adc09aa60628343))

# [@cloudgraph/policy-pack-aws-cis-1.2.0-v0.13.0](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.12.1...@cloudgraph/policy-pack-aws-cis-1.2.0@0.13.0) (2022-08-01)


### Features

* Update rules and sdk package version ([450b676](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/450b676836834634190c792e5a0e311dd41e5551))

# [@cloudgraph/policy-pack-aws-cis-1.2.0-v0.12.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.12.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.12.1) (2022-07-11)


### Bug Fixes

* update .npmignore to include all rules in package ([3dd7a87](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3dd7a874ee4ff52ae8d6f948f39dcf8655eeda87))

# [@cloudgraph/policy-pack-aws-cis-1.2.0-v0.12.0](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.11.3...@cloudgraph/policy-pack-aws-cis-1.2.0@0.12.0) (2022-07-11)


### Bug Fixes

* add validation for null references ([ddd7f53](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ddd7f537b1843b14fee55690e61bbdd605386daf))
* add validation for null references ([bb9811a](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/bb9811a977595260db3204165350821bebd30a50))
* fixed unit tests ([3f454f2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3f454f220ea0d1b73721a343a52f06c30619508b))


### Features

* fixed and migrated rules from jq to js (rules-exclude branch) ([ba9a6f6](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ba9a6f607acbe85cdfc291fd2075681d96122fe5))
* fixed and migrated rules from jq to js (rules-exclude branch) ([7c426ca](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/7c426ca709b68bc0af8bfad96e50e3bcf31eaca2))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.11.2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.11.1...@cloudgraph/policy-pack-aws-cis-1.2.0@0.11.2) (2022-06-28)


### Bug Fixes

* **checks:** Fix how we check security groups ([76c333b](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/76c333ba2b083826d2348d964d1a1ae3fc733711))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.11.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.11.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.11.1) (2022-06-28)


### Bug Fixes

* **checks:** Make AWS CIS 1.21 rule manual ([1a50e68](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/1a50e68139c1b7fac5fda2d2c946ddded21cf2b4))

# @cloudgraph/policy-pack-aws-cis-1.2.0 [0.11.0](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.10.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.11.0) (2022-05-02)


### Bug Fixes

* rename vpc flowLogs connection to FlowLog ([c31e985](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/c31e985b4a2623fb01f8a29a4c5897becb2e4905))
* Updated policy field for S3 schema ([dc3d6c8](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/dc3d6c8b4b7e22ba58c1394d0b64e866ab3de519))


### Features

* Included 6.x rules for aws nist 800-53 ([b51f652](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b51f6522e7721928ea8dc30d009ac5530f6e86eb))

# @cloudgraph/policy-pack-aws-cis-1.2.0 [0.11.0-beta.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.10.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.11.0-beta.1) (2022-05-02)


### Bug Fixes

* rename vpc flowLogs connection to FlowLog ([c31e985](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/c31e985b4a2623fb01f8a29a4c5897becb2e4905))
* Updated policy field for S3 schema ([dc3d6c8](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/dc3d6c8b4b7e22ba58c1394d0b64e866ab3de519))


### Features

* Included 6.x rules for aws nist 800-53 ([b51f652](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b51f6522e7721928ea8dc30d009ac5530f6e86eb))

# @cloudgraph/policy-pack-aws-cis-1.2.0 [0.11.0-alpha.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.10.1-alpha.1...@cloudgraph/policy-pack-aws-cis-1.2.0@0.11.0-alpha.1) (2022-04-27)


### Features

* Included 6.x rules for aws nist 800-53 ([b51f652](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/b51f6522e7721928ea8dc30d009ac5530f6e86eb))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.10.1-alpha.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.10.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.10.1-alpha.1) (2022-04-26)


### Bug Fixes

* rename vpc flowLogs connection to FlowLog ([c31e985](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/c31e985b4a2623fb01f8a29a4c5897becb2e4905))
* Updated policy field for S3 schema ([dc3d6c8](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/dc3d6c8b4b7e22ba58c1394d0b64e866ab3de519))

# @cloudgraph/policy-pack-aws-cis-1.2.0 [0.10.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.9.3...@cloudgraph/policy-pack-aws-cis-1.2.0@0.10.0) (2022-04-01)


### Features

* Included 1.x rules for aws nist 800-53 ([826218c](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/826218c91a7c150f21b78828e20cbfcf6a39564e))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.9.3](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.9.2...@cloudgraph/policy-pack-aws-cis-1.2.0@0.9.3) (2022-03-18)


### Bug Fixes

* Fixed broken aws cis 1.2.0 rule (1.14) ([0450270](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/0450270dbb39ed157732f46e0e3714f12b964f26))
* Fixed CloudTrail checks ([4e21578](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/4e21578bb4ee7bdf681b1191ed60a431999db52b))
* Fixed rule 3.3 for AWS CIS 1.2.0 ([5df0818](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/5df081849be81948ee018345250d7f319810415d))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.9.2](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.9.1...@cloudgraph/policy-pack-aws-cis-1.2.0@0.9.2) (2022-03-11)


### Bug Fixes

* Fixed broken aws cis 1.2.0 rule (1.14) ([fd83b23](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/fd83b23ab8905a37bdcd97086472ec44c9608917))
* Fixed rule 1.10 for AWS CIS 1.2.0 ([7ba6a7b](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/7ba6a7bc6b6bb39e514c02d441d6a974ef24a91e))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.9.1](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.9.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.9.1) (2022-03-11)


### Bug Fixes

* Fix discrepancies between AutoCloud and Fugue ([e5d5de6](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/e5d5de6bbcd72632c4c2cfbfac5d2baccd4b529f))

# @cloudgraph/policy-pack-aws-cis-1.2.0 [0.9.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.8.4...@cloudgraph/policy-pack-aws-cis-1.2.0@0.9.0) (2022-03-10)


### Bug Fixes

* **checks:** update kms cis checks for updates to kms schema ([390cd44](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/390cd4447f5b30c391f0b770791db1137c317f07))


### Features

* **checks:** new check kms-check-1 ([3970287](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/3970287d9954d8748a7251cfb2748b16f7ea3cf1))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.8.4](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.8.3...@cloudgraph/policy-pack-aws-cis-1.2.0@0.8.4) (2022-03-09)


### Bug Fixes

* **checks:** remove (scored) / (not scored) from all checks ([a6ac685](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/a6ac685ed1ff2fa4850a9c96785b06d41e4bf4cc))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.8.3](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.8.2...@cloudgraph/policy-pack-aws-cis-1.2.0@0.8.3) (2022-02-22)


### Bug Fixes

* Removed arn from iamPasswordPolicy ([0fefcb1](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/0fefcb132e5b28292b9b7221f1bcf7b52c057e58))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.8.2](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.8.1...@cloudgraph/policy-pack-aws-cis-1.2.0@0.8.2) (2022-02-16)


### Bug Fixes

* **rule:** simplify rule 1.2 logic ([cc64525](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/cc64525fd44c73af8a3fbb951d45a39409e2318f))
* **rule:** update rules 1.2,1.3,1.4 to handle cases that should pass that were failing ([8afd40f](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/8afd40f5082cb01e03a7f47f9aa0603b1d8c3735))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.8.1](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.8.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.8.1) (2022-02-10)


### Bug Fixes

* Included additional fields to aws rules ([8f7c9fa](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/8f7c9fa575d20f043cb9557d6734a0967762753d))

# @cloudgraph/policy-pack-aws-cis-1.2.0 [0.8.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.7.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.8.0) (2022-02-10)


### Features

* Included cis 2.3 rule for aws cis 1.2.0 ([c8a279e](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/c8a279e5cb8ca84f38aa2db035d8b30a2040efaf))

# @cloudgraph/policy-pack-aws-cis-1.2.0 [0.7.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.6.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.7.0) (2022-02-07)


### Features

* Included cis 1.15, 1.17, 1.18, 1.19 rules for aws cis 1.2.0 ([a404324](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/a404324dc78c192c0eec6656ecfd45f9867f1f22))
* Included cis 1.20, 1.21, 1.22 rules for aws cis 1.2.0 ([0e6116d](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/0e6116d38f17929e0ee376b2e96d3525e04b5c61))
* Included cis 2.5 rule for aws cis 1.2.0 ([d61d368](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/d61d36818db2478445283516ee9b58f676de4565))

# @cloudgraph/policy-pack-aws-cis-1.2.0 [0.6.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.5.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.6.0) (2022-02-07)


### Bug Fixes

* Added title for aws rules ([d683ebe](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/d683ebe295c3348783c43881f3e742bcd688fc9d))


### Features

* Included cis 1.9, 1.10, 1.11 rules for gcp cis 1.2.0 ([88d5134](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/88d513443a9dab9fa921d8ad3f648c4ee47a7e42))

# @cloudgraph/policy-pack-aws-cis-1.2.0 [0.5.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.4.2...@cloudgraph/policy-pack-aws-cis-1.2.0@0.5.0) (2022-02-01)


### Bug Fixes

* **rule:** update rule references where incorrect ([bf9ff77](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/bf9ff77172f5b07ea2c33304534b28b9aa128248))
* formatting ([8212e02](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/8212e0289ba1abc252207777fc729c3c0f5652e6))
* **rule:** update cis 1.1 rule to have audit, remediation, rationale, and references fields ([64ab016](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/64ab0164b7bcc441ff0fcadbe518be2dc738cde6))
* **rule:** update reference link to just be a link ([d3a55ba](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/d3a55ba51f707973813d3c35c15b1a1265f9f39c))
* **rule:** update some formatting ([a4654f1](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/a4654f1bcd69766af5e485934e692a18204c26e5))


### Features

* CIS info for rules up to 3.6 ([323d787](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/323d787f453f4d0b5b80335337c3c4aa6e3ec673))
* CIS info for rules up to 4.3 ([97c5ac7](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/97c5ac76813eaf937de4e7dc51cd979a110729b5))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.4.2](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.4.1...@cloudgraph/policy-pack-aws-cis-1.2.0@0.4.2) (2022-01-19)


### Bug Fixes

* Exported missing rule 1.1 for aws cis ([c8755c0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/c8755c0a8c0a4e17e19a9e084a28005d5956c0a4))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.4.1](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.4.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.4.1) (2022-01-12)


### Bug Fixes

* Updated severity levels to new ones ([658da29](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/658da29de227fbc4074422ba728b8a07b3ef987b))

# @cloudgraph/policy-pack-aws-cis-1.2.0 [0.4.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.3.1...@cloudgraph/policy-pack-aws-cis-1.2.0@0.4.0) (2022-01-10)


### Features

* cis 3.6, 3.7, 3.8, 3.9 rules for cis 1.2.0 ([9fe01f3](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/9fe01f366e0498ea77acc3c55fa0e8905a3dc9c6))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.3.1](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.3.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.3.1) (2022-01-10)


### Bug Fixes

* Added missed bracket to rule 4.3 ([4da9d1b](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/4da9d1b21f89838fdf636bebeecdeda674f328e2))

# @cloudgraph/policy-pack-aws-cis-1.2.0 [0.3.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.2.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.3.0) (2022-01-10)


### Bug Fixes

* Fixed rule 1.1 using not operator ([7ec5463](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/7ec5463c358c5e66cc406980bbbb4fb5777192a2))
* Updated rules with new sdk operators ([69b0bf2](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/69b0bf242ff7539319f881162cb5644b0d2244a6))


### Features

* Included 3.10, 3.11, 3.12, 3.13, 3.14 rules for cis 1.2.0 ([5c63238](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/5c63238385141c19640153cfeab4a28a414e7108))
* Included rule 3.1 for AWS CIS ([bd8afc8](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/bd8afc8d5b2a8c158c7d67b0d80cc87708d13669))
* Included rule 3.2 for AWS CIS ([c4d59a9](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/c4d59a907293655245847d54f78f175df0186c73))
* Included rule 3.3 for AWS CIS ([d2f3482](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/d2f34822054e7d21ed7707dc01d34679dd41a4f2))
* Included rule 3.4 for AWS CIS ([079fd77](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/079fd773fb82f94e4e4f4fc16ea939a68575d54a))
* Included rule 3.5 for AWS CIS ([37f1bc3](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/37f1bc335a4eb92d3014f9e921eeaae053af9d46))

# @cloudgraph/policy-pack-aws-cis-1.2.0 [0.2.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.1.2...@cloudgraph/policy-pack-aws-cis-1.2.0@0.2.0) (2022-01-10)


### Features

* Included 3.10, 3.11, 3.12, 3.13, 3.14 rules for cis 1.2.0 ([ecea973](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/ecea9739f19984b96d96b251670f087baeff14ec))
* Included 4.1, 4.2, 4.3 rules for cis 1.2.0 ([69f9635](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/69f9635e1b1505ff82db579f6cfad2afb2979f05))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.1.2](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.1.1...@cloudgraph/policy-pack-aws-cis-1.2.0@0.1.2) (2022-01-04)


### Bug Fixes

* Updated sdk and tests references ([8b9b9f8](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/8b9b9f8eaca504d1075569c06a8e897c455c0fe4))

## @cloudgraph/policy-pack-aws-cis-1.2.0 [0.1.1](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.1.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.1.1) (2021-12-30)


### Bug Fixes

* Exported 2.x rules ([483552e](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/483552ebb3b9dbc01c5306e33a2b720216b94ab4))

# @cloudgraph/policy-pack-aws-cis-1.2.0 [0.1.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.0.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.1.0) (2021-12-30)


### Bug Fixes

* Added severity new field to existing rules ([19ce946](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/19ce9465726fcc5fffb208e9b430dcecd658347d))
* Fixed 1.x rules using new rules engine version ([ac24abf](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/ac24abfa7ff49cb656a5b62fd7bcfb9847b9f2ae))
* Fixed cis 1.30 rules with severity field ([dfa7b25](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/dfa7b2542603cb038bfc2783cdf11562cab05e2b))
* Removed white space from comment ([e907a99](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/e907a9927ca0356062a13053f05e24f449e715c7))


### Features

* Included 2.1 rule for cis 1.2.0 ([b37f19b](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/b37f19b295438084066141e26b719e8965007042))
* Included 2.2 rule for cis 1.2.0 ([54f8408](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/54f8408610be3590f775eb6bb2ba5377bda9f587))
* Included 2.4 rule for cis 1.2.0 ([ba1af5c](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/ba1af5c094de3c63ac3b9e10dc5689991723c015))
* Included 2.6 rule for cis 1.2.0 ([f7f129d](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/f7f129ded06d0259de5fe013298674545db12d8b))
* Included 2.7 rule for cis 1.2.0 ([b49e383](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/b49e38332d99aff29877f2f7da5fbbca93d7e62b))
* Included 2.8 rule for cis 1.2.0 ([210144a](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/210144ab24eae33c369db84f59b18142d89f352a))
* Included 2.9 rule for cis 1.2.0 ([74f6011](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/74f6011a83a9abe34809c89da45605c321607a8f))
* release new versions ([8b62994](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/8b629948a7f527fcd54f2bff8a54ad42802d5887))

# @cloudgraph/policy-pack-aws-cis-1.2.0 [0.1.0-alpha.1](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-aws-cis-1.2.0@0.0.0...@cloudgraph/policy-pack-aws-cis-1.2.0@0.1.0-alpha.1) (2021-12-22)


### Bug Fixes

* Added severity new field to existing rules ([19ce946](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/19ce9465726fcc5fffb208e9b430dcecd658347d))
* Fixed 1.x rules using new rules engine version ([ac24abf](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/ac24abfa7ff49cb656a5b62fd7bcfb9847b9f2ae))
* Fixed cis 1.30 rules with severity field ([dfa7b25](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/dfa7b2542603cb038bfc2783cdf11562cab05e2b))
* Removed white space from comment ([e907a99](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/e907a9927ca0356062a13053f05e24f449e715c7))


### Features

* Included 2.1 rule for cis 1.2.0 ([b37f19b](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/b37f19b295438084066141e26b719e8965007042))
* Included 2.2 rule for cis 1.2.0 ([54f8408](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/54f8408610be3590f775eb6bb2ba5377bda9f587))
* Included 2.4 rule for cis 1.2.0 ([ba1af5c](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/ba1af5c094de3c63ac3b9e10dc5689991723c015))
* Included 2.6 rule for cis 1.2.0 ([f7f129d](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/f7f129ded06d0259de5fe013298674545db12d8b))
* Included 2.7 rule for cis 1.2.0 ([b49e383](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/b49e38332d99aff29877f2f7da5fbbca93d7e62b))
* Included 2.8 rule for cis 1.2.0 ([210144a](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/210144ab24eae33c369db84f59b18142d89f352a))
* Included 2.9 rule for cis 1.2.0 ([74f6011](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/74f6011a83a9abe34809c89da45605c321607a8f))
* release new versions ([8b62994](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/8b629948a7f527fcd54f2bff8a54ad42802d5887))
