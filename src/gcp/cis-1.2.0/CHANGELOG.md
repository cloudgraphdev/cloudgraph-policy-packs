## [1.24.1-alpha.2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.24.1-alpha.1...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.24.1-alpha.2) (2023-05-17)


### Bug Fixes

* fix rule publication ([05da425](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/05da4255583ed119a06ca01710e194b62e2d2499))

## [1.24.1-alpha.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.24.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.24.1-alpha.1) (2023-05-17)


### Bug Fixes

* **checks:** Cannot read properties of undefined (reading 'direction') ([700a3de](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/700a3de4f5a7893aa9cba2238be485dc2254e7a6))

# [1.24.0](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.23.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.24.0) (2023-04-28)


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

# [@cloudgraph/policy-pack-gcp-cis-1.2.0-v1.23.1-alpha.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.23.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.23.1-alpha.1) (2022-12-14)


### Bug Fixes

* **pnpm:** using semantic-release-pnpm ([eb9f3f2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/eb9f3f22e85375b79be205c62adc09aa60628343))

# [@cloudgraph/policy-pack-gcp-cis-1.2.0-v1.23.0](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.22.1...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.23.0) (2022-08-01)


### Features

* Update rules and sdk package version ([450b676](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/450b676836834634190c792e5a0e311dd41e5551))

# [@cloudgraph/policy-pack-gcp-cis-1.2.0-v1.22.1](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.22.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.22.1) (2022-07-11)


### Bug Fixes

* update .npmignore to include all rules in package ([3dd7a87](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3dd7a874ee4ff52ae8d6f948f39dcf8655eeda87))

# [@cloudgraph/policy-pack-gcp-cis-1.2.0-v1.22.0](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.21.1...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.22.0) (2022-07-11)


### Bug Fixes

* add validation for null references ([ddd7f53](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ddd7f537b1843b14fee55690e61bbdd605386daf))
* fixed unit tests ([3f454f2](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/3f454f220ea0d1b73721a343a52f06c30619508b))


### Features

* fixed and migrated rules from jq to js (rules-exclude branch) ([ba9a6f6](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/ba9a6f607acbe85cdfc291fd2075681d96122fe5))
* fixed and migrated rules from jq to js (rules-exclude branch) ([7c426ca](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/7c426ca709b68bc0af8bfad96e50e3bcf31eaca2))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.21.0](https://github.com/cloudgraphdev/cloudgraph-policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.20.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.21.0) (2022-05-26)


### Bug Fixes

* [GCP] Fix discrepancies between AutoCloud and Fugue ([7227bc6](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/7227bc637eece1fa8a04e8aca8daa24d051c9dbe))


### Features

* Support GCP PCI rules - Part 2 ([86be981](https://github.com/cloudgraphdev/cloudgraph-policy-packs/commit/86be9816667dfe107f946a8cde90533fb6564f91))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.20.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.19.1...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.20.0) (2022-03-17)


### Bug Fixes

* GCP rule CIS 4.3 fails when there is no meta data ([a002ed9](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/a002ed94367ebc7c40f89c74a840add816f9b8f0))


### Features

* GCP rule 3.9 could present a [secure] failure if a Policy is insecure, but it's not used by a proxy ([b91265a](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/b91265a59adf2291a7cc8c49e55cccc5156a59cf))

## @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.19.1](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.19.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.19.1) (2022-02-25)


### Bug Fixes

* **connections:** gcp pluralization top level connections ([f6aa059](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/f6aa059c9507965ae3e8d289521b0a99dca1d1ed))
* **connections:** gcp pluralization top level connections ([b8d36ef](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/b8d36ef08513bd6c2f62dde2122153903c812704))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.19.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.18.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.19.0) (2022-02-17)


### Bug Fixes

* **gcp-cis-1.2.0-1.14:** add rationale ([ac4ad2f](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/ac4ad2f2f76893da4cf201968a3653aafbe91e9b))
* **gcp-cis-1.2.0-1.14:** removed query/conditions for manual check ([47bb43d](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/47bb43d23b80c170cc3724417db069e1307eda8e))
* **rule:** update rules 1.2,1.3,4.10 tiles to add gcp prefix ([abe6fbf](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/abe6fbfa27b13231336b80b0c144815bd2a88bd4))


### Features

* Add 1.14 rule for gcp cis 1.2.0 ([42e263a](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/42e263a3073fd4dfc8b8a455c683e43f7c744d36))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.18.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.17.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.18.0) (2022-02-10)


### Features

* Included 7.1, 7.2, 7.3 rules for gcp cis 1.2.0 ([aae43f0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/aae43f0a3f911b890adf4291f8c112adaed8bb61))
* Included cis 2.1 rule for cis 1.2.0 ([eddb6e0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/eddb6e0e6967d8e110534f5f7c1f43b64b0b3ffd))
* Included cis 6.1.1 manual rule for cis 1.2.0 ([fe9cc82](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/fe9cc8207371bc9558f7b6cd2967bb9c223125cf))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.17.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.16.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.17.0) (2022-02-08)


### Features

* Included cis 6.1.1 manual rule for cis 1.2.0 ([c0e3b22](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/c0e3b2268fe8c4895e3a990fbe6c34d87969c6e8))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.16.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.15.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.16.0) (2022-02-07)


### Bug Fixes

* Added title to gcp rules ([5221b86](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/5221b86ef2f73b8275ee64440b741e09c05ce3c5))


### Features

* Included cis 1.9, 1.10, 1.11 rules for gcp cis 1.2.0 ([88d5134](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/88d513443a9dab9fa921d8ad3f648c4ee47a7e42))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.15.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.14.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.15.0) (2022-02-02)


### Features

* Included cis 1.4, 1.7 rules for gcp cis 1.2.0 ([b9f0cc8](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/b9f0cc837756927426d39e9827168062aaa97fba))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.14.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.13.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.14.0) (2022-02-01)


### Bug Fixes

* **rule:** update rule references where incorrect ([bf9ff77](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/bf9ff77172f5b07ea2c33304534b28b9aa128248))


### Features

* GCP CIS 1.2 section 1 info ([61b51f9](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/61b51f9c8092e17a4824c249817668ffe00f4ef3))
* GCP CIS 1.2 section 2x first half ([0b080b8](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/0b080b8ebbab9840fd48616f6592262af160278f))
* GCP CIS 1.2 section 2x second half ([dfe6843](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/dfe6843a18c790a5dca2a0ffc1b57f42a2cf723a))
* GCP CIS 1.2 section 3x ([696aae8](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/696aae8d7e21d44bc56fd927adb5a8dc7d21d5f3))
* GCP CIS 1.2 section 4x & 5x ([855806e](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/855806e1c32ac0d683edf7cefd1a94f4f8326046))
* GCP CIS 1.2 section 6x ([be23f46](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/be23f46e0b12a40938a0a8ca2b51223660d48c7a))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.13.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.12.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.13.0) (2022-02-01)


### Features

* Included CIS 5.1 rule for cis 1.2.0 ([6d8f70b](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/6d8f70b043b1f44229a073f7a3bed106c87eb4b8))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.12.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.11.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.12.0) (2022-02-01)


### Features

* Included cis 1.2 and 1.3 manual rules for cis 1.2.0 ([dfbd86d](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/dfbd86d688b773c6af26201fd25173c818f0ee4d))
* Included CIS 4.4 rule for cis 1.2.0 ([692648e](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/692648eff3f8bc842bb03b4b9815cebad0932a7b))
* Included first manual rule 4.10 for GCP CIS ([85c586c](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/85c586c595181d9df6721da58318e4e34608fe7e))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.11.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.10.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.11.0) (2022-01-31)


### Features

* Included cis 1.12, 1.13, 1.15 rules for gcp cis 1.2.0 ([9740c88](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/9740c88afd5bbd5377910a9e01a3ad29ec5e0ff5))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.10.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.9.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.10.0) (2022-01-28)


### Features

* Included cis 6.3.1, 6.3.2, 6.3.3, 6.3.4, 6.3.5, 6.3.6, 6.3.7 rules for gcp cis 1.2.0 ([f9258f1](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/f9258f12af3f6503d026172666a072d8acba1691))
* Included cis 6.4, 6.5, 6.6, 6.7 rules for gcp cis 1.2.0 ([e4e9341](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/e4e9341e02a076ccfe82ab3c4a2f412b11ce07ae))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.9.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.8.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.9.0) (2022-01-26)


### Features

* Included cis 6.1.2, 6.1.3, 6.2.1, 6.2.2, 6.2.3, 6.2.4, 6.2.5, 6.2.6, 6.2.7, 6.2.8, 6.2.9, 6.2.10. 6.2.11, 6.2.12, 6.2.13, 6.2.14, 6.2.15, 6.2.16 rules for gcp cis 1.2.0 ([12ba8c8](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/12ba8c8ad21bc272f91b57cc14ae79e7dd043ff1))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.8.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.7.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.8.0) (2022-01-26)


### Features

* Included cis 1.1, 1.5, 1.6, 1.8 rules for gcp cis 1.2.0 ([07ca8ee](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/07ca8ee01f42a7c9df073a6e6d8295793f1209dd))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.7.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.6.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.7.0) (2022-01-25)


### Features

* Included cis 3.9 rule for gcp cis 1.2.0 ([ea761b4](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/ea761b4a6441619007e5fad4164233f58ad91e2f))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.6.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.5.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.6.0) (2022-01-24)


### Features

* Included cis 2.4, 2.5, 2.6, 2.7, 2.8 rules for gcp cis 1.2.0 ([0c2173d](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/0c2173d4b27e6618f45c6fc3f6245114906ad17f))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.5.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.4.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.5.0) (2022-01-19)


### Features

* Included cis 2.2, 2.3 rules for gcp cis 1.2.0 ([022c3a9](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/022c3a97293a552ab3e802a71f5cc188cee14646))
* Included cis 4.1, 4.2, 4.3, 4.5, 4.6, 4.7 rules for gcp cis 1.2.0 ([56606c3](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/56606c3090748be48f115448e63646db2b0dc72f))
* Included cis 5.2 rule for gcp cis 1.2.0 ([92dad2c](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/92dad2c2ad399357b5ced7e74f4c2fc00aa01717))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.4.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.3.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.4.0) (2022-01-19)


### Features

* Included cis cis 4.8, 4.9, 4.11 rules for gcp cis 1.2.0 ([e8f50fe](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/e8f50fe53d9bdea5d1153dbcef91db0c30e8b228))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.3.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.2.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.3.0) (2022-01-18)


### Features

* Includes cis 2.9, 2.10, 2.11, 2.12 for gcp cis 1.2.0 ([401ce96](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/401ce96b16e78574b967968e01be60f5079eb053))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.2.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.1.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.2.0) (2022-01-17)


### Features

* Included cis 3.1, 3.2, 3.3, 3.4, 3.5 rules for gcp cis 1.2.0 ([6b9dbd3](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/6b9dbd37caf06b4970d9fa7f2f1677645400c8db))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 [1.1.0](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/compare/@cloudgraph/policy-pack-gcp-cis-1.2.0@1.0.0...@cloudgraph/policy-pack-gcp-cis-1.2.0@1.1.0) (2022-01-17)


### Features

* Included cis 3.10 rule for gcp cis 1.2.0 ([2df0286](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/2df02867fc83de3fdbc4d9f67bc10af43289444b))
* Included cis 3.8 rule for gcp cis 1.2.0 ([2cfba76](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/2cfba7677bb8b010d3a67368e5fe66fd2487fe5f))

# @cloudgraph/policy-pack-gcp-cis-1.2.0 1.0.0 (2022-01-12)


### Features

* Included cis 3.6, 3.7 rules for gcp cis 1.2.0 ([8ce25b6](https://gitlab.com/auto-cloud/cloudgraph/policy-packs/commit/8ce25b6bff826196ea360d96945b6160d0b0ceb8))
