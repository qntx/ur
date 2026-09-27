export const seedC709 = {
  payloadHex: "c7098580125e2ab0981253468b2dbc52",
  cborHex: "a10150c7098580125e2ab0981253468b2dbc52",
  ur: "ur:seed/oyadgdstaslplabghydrpfmkbggufgludprfgmamdpwmox",
  digestHex: "e824467caffeaf3bbc3e0ca095e660a9bad80ddb6a919433a37161908b9a3986",
} as const;

export const seedYinmn = {
  payloadHex: "59f2293a5bce7d4de59e71b4207ac5d2",
  cborHex: "a1015059f2293a5bce7d4de59e71b4207ac5d2",
  ur: "ur:seed/oyadgdhkwzdtfthptokigtvwnnjsqzcxknsktdhpyljeda",
} as const;

export const seedYinmnFull = {
  payloadHex: "59f2293a5bce7d4de59e71b4207ac5d2",
  epochSeconds: 1_645_539_742,
  name: "Yinmn Blue Acid Exam",
  note: "This is our standard 128-bit test seed.",
  cborHex:
    "a4015059f2293a5bce7d4de59e71b4207ac5d202c11a6214f19e037459696e6d6e20426c75652041636964204578616d04782754686973206973206f7572207374616e64617264203132382d626974207465737420736565642e",
  ur: "ur:seed/oxadgdhkwzdtfthptokigtvwnnjsqzcxknsktdaosecyidbbwnnnaxjyhkinjtjnjtcxfwjzkpihcxfpiainiecxfekshsjnaaksdighisinjkcxinjkcxjlkpjpcxjkjyhsjtiehsjpiecxeheyetdpidinjycxjyihjkjycxjkihihiedmksjpaate",
} as const;

/** BCR-2020-006 historical example: creation-date tag 100. Negative test only. */
export const seedHistoricalTag100Ur =
  "ur:seed/oeadgdstaslplabghydrpfmkbggufgludprfgmaotpiecffltnlpqdenos" as const;

/**
 * Official crypto-seed vector, BCR-2020-006 papers/bcr-2020-006-urtypes.md @
 * bd51df477da12d49f09f1727b018b5cb50c6e929. Body carries creation-date tag 100, which stays
 * rejected: negative test only.
 */
export const seedHistoricalTag100V1Ur =
  "ur:crypto-seed/oeadgdstaslplabghydrpfmkbggufgludprfgmaotpiecffltnlpqdenos" as const;

/**
 * No official v1 seed UR without tag 100 exists; token swapped on the v2 c709 golden (v1/v2 bodies
 * share the CDDL).
 */
export const seedC709V1Ur =
  "ur:crypto-seed/oyadgdstaslplabghydrpfmkbggufgludprfgmamdpwmox" as const;

export const psbt167 = {
  cborHex:
    "58a770736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000",
  ur: "ur:psbt/hdosjojkidjyzmadaenyaoaeaeaeaohdvsknclrejnpebncnrnmnjojofejzeojlkerdonspkpkkdkykfelokgprpyutkpaeaeaeaeaezmzmzmzmlslgaaditiwpihbkispkfgrkbdaslewdfycprtjsprsgksecdratkkhktikewdcaadaeaeaeaezmzmzmzmaojopkwtayaeaeaeaecmaebbtphhdnjstiambdassoloimwmlyhygdnlcatnbggtaevyykahaeaeaeaecmaebbaeplptoevwwtyakoonlourgofgvsjydpcaltaemyaeaeaeaeaeaeaeaeaebkgdcarh",
} as const;

/**
 * Official crypto-psbt vector, BCR-2020-006 papers/bcr-2020-006-urtypes.md @
 * bd51df477da12d49f09f1727b018b5cb50c6e929.
 */
export const psbt167V1Ur =
  "ur:crypto-psbt/hdosjojkidjyzmadaenyaoaeaeaeaohdvsknclrejnpebncnrnmnjojofejzeojlkerdonspkpkkdkykfelokgprpyutkpaeaeaeaeaezmzmzmzmlslgaaditiwpihbkispkfgrkbdaslewdfycprtjsprsgksecdratkkhktikewdcaadaeaeaeaezmzmzmzmaojopkwtayaeaeaeaecmaebbtphhdnjstiambdassoloimwmlyhygdnlcatnbggtaevyykahaeaeaeaecmaebbaeplptoevwwtyakoonlourgofgvsjydpcaltaemyaeaeaeaeaeaeaeaeaebkgdcarh" as const;

export const hdkey1 = {
  keyDataHex: "00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
  chainCodeHex: "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
  cborHex:
    "a301f503582100e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35045820873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
  ur: "ur:hdkey/otadykaxhdclaevswfdmjpfswpwkahcywspsmndwmusoskprbbehetchsnpfcybbmwrhchspfxjeecaahdcxltfszmlyrtdlgmhfcnzcctvwcmkbpsftgonbgauefsehgrqzdmvodizmweemtlaybakiylat",
} as const;

export const hdkey2 = {
  keyDataHex: "026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6",
  chainCodeHex: "ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c85",
  parentFingerprint: 0xe9181cf3,
  cborHex:
    "a5035821026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6045820ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c8505d99d71a1020106d99d70a1018a182cf501f501f500f401f4081ae9181cf3",
  ur: "ur:hdkey/onaxhdclaojlvoechgferkdpqdiabdrflawshlhdmdcemtfnlrctghchbdolvwsednvdztbgolaahdcxtottgostdkhfdahdlykkecbbweskrymwflvdylgerkloswtbrpfdbsticmwylklpahtantjsoyaoadamtantjooyadlecsdwykadykadykaewkadwkaycywlcscewfjnkpvllt",
  digestSourceHex:
    "845821026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a65820ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c850001",
  digestHex: "362af3038da7600ad1581c19161c8594aafafc24e5acf1aefc8f7a0bbe366df2",
} as const;

/**
 * Official crypto-hdkey vector 1, BCR-2020-007 papers/bcr-2020-007-hdkey.md @
 * cd36feeed50f5d261726b78c31873845effc6792.
 */
export const hdkey1V1Ur =
  "ur:crypto-hdkey/otadykaxhdclaevswfdmjpfswpwkahcywspsmndwmusoskprbbehetchsnpfcybbmwrhchspfxjeecaahdcxltfszmlyrtdlgmhfcnzcctvwcmkbpsftgonbgauefsehgrqzdmvodizmweemtlaybakiylat" as const;

/** Official crypto-hdkey vector 2, same source: nested use-info tag 305 and origin tag 304. */
export const hdkey2V1Ur =
  "ur:crypto-hdkey/onaxhdclaojlvoechgferkdpqdiabdrflawshlhdmdcemtfnlrctghchbdolvwsednvdztbgolaahdcxtottgostdkhfdahdlykkecbbweskrymwflvdylgerkloswtbrpfdbsticmwylklpahtaadehoyaoadamtaaddyoyadlecsdwykadykadykaewkadwkaycywlcscewfihbdaehn" as const;

/** Hdkey2 body with nested tags 40305/40304 swapped to v1 305/304, matching hdkey2V1Ur. */
export const hdkey2V1CborHex =
  "a5035821026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6045820ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c8505d90131a1020106d90130a1018a182cf501f501f500f401f4081ae9181cf3" as const;

export const envelopeAlice = {
  cborHex: "d8c965416c696365",
  wrappedCborHex: "d8c8d8c965416c696365",
} as const;

export const envelopeNode = {
  cborHex: "82d8c965416c696365a1d8c9656b6e6f7773d8c963426f62",
  ur: "ur:envelope/lftpsoihfpjziniaihoytpsoihjejtjlktjktpsoiafwjlidutgmnnns",
} as const;

/** BCR-2020-011 third share. identifier 0x4bbf, GT=2, G=2, GI=0, T=2, reserved=0, I=2. */
export const sskrShare = {
  identifier: 0x4bbf,
  groupThreshold: 2,
  groupCount: 2,
  groupIndex: 0,
  memberThreshold: 2,
  memberIndex: 2,
  shareValueHex: "5abd490ee65b6084859854ee67736e75",
  cborHex: "554bbf1101025abd490ee65b6084859854ee67736e75",
  ur: "ur:sskr/gogrrsbyadaohtrygabavahphnlrlpmkghwyiojkjtkpmdkncfjp",
} as const;

/**
 * Official crypto-sskr third share, BCR-2020-011 papers/bcr-2020-011-sskr.md @
 * 58272f8c65deca9721cf30d58de92e1bca371615.
 */
export const sskrV1Ur =
  "ur:crypto-sskr/gogrrsbyadaohtrygabavahphnlrlpmkghwyiojkjtkpmdkncfjp" as const;
