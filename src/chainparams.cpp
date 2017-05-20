// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "base58.h"

using namespace std;

#include "chainparamsseeds.h"

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "AMI";
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 2;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");  // Lowered
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        /**
         * The message start string should be awesome! ⓩ❤
         */
        pchMessageStart[0] = 0x24;
        pchMessageStart[1] = 0xe9;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x64;
        /* TODO: create AMI key */ vAlertPubKey = ParseHex("048679fb891b15d0cada9692047fd0ae26ad8bfb83fabddbb50334ee5bc0683294deb410be20513c5af6e7b9cec717ade82b27080ee6ef9a245c36a795ab044bb3");
        nDefaultPort = 8099; // 8133 - 100 + 66
        nMinerThreads = 0;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        /**
         * Build the genesis block. Note that the output of its generation
         * transaction cannot be spent since it did not originally exist in the
         * database (and is in any case of zero value).
         *
         * >>> from pyblake2 import blake2s
         * >>> 'AMICoin' + blake2s(b'No taxation without representation. BTC #437541 - 00000000000000000397f175a94dd3f530b957182eb2a9f7b79a44a94a5e0450').hexdigest()
         */
        const char* pszTimestamp = "AMICoin860413afe207aa173afee4fcfa9166dc745651c754a41ea8f155646f5aa828ac";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 4;
        genesis.nTime    = 1494680115;
        genesis.nBits    = 0x2007ffff; // WAS 0x1f07ffff;
        genesis.nNonce   = uint256S("0x0000000000000000000000000000000000000000000000000000000000000222");
        genesis.nSolution = ParseHex("0019f7206640383834adf15a693edde50ebbebaf8d1ed526ad628c918f795dc2a3cae776f0c1a62e089d048ede10289caad59013231366c8a2e375585ecc263f1f14b458dc37a79f8c246c3365a38a447dbbef5e01b490c207442841055a2095fe94ff60a9cc5655f713cb25e2740ffe05536aa292bf355aa120efb652d424cd1eb2a4b4400dbc03954c4c30fbaa1adf946a0b28a95658815bb3a752bcd2d732ffc331fc06db948600d511b807c7a978961a93215d557fba57e1393c711685b23f24e07eff1fc80301a2411e5dca8176a2da0883dd30a99ff4c97c5d020aa09a3da9f1947491fe61998351d0f9244fcb50fbadee6656c32fea5b5f1b01924c734af6f21feb33433e781ad07e6289babe85128dc2f76146a60103f0b30cefa6234a633b980ced04c416ac8f8787ac8d17167957bf3f42a9869991f51895b1750b9ff00bdd6123df974884f676cd7ce3b50338eba3a95c04232718c2a06c1b4585e1ef7a8e6b0fc043a76b2a8107d88396a83458f19212761102d811ceb2b2317295f1e3728328a9770f02b533f7c5c119a47d584476e2a5dbc0d2e5902ead5f05ca1f3d8421ea4ac9c591e6f2a2be53d30eaf9302a24b5cddb02ba44481f4d53fad86e585048dcbff2a43d1b9db8528d84e9479a60d8d5a3074b359391bb614d113358e3889c1e5ac2e5fd9f6e9b3e83dbcb0ff81fc1c914408d7e7b11dee32a39ce9a33114dcedffabd05da45e369a9d94c4f9c9dfcec88374b0f2a6ee8cad1af90b10b86dad4b5ab5dafc763335ad6712511eba163dae59a1a6a4d1e5298d4b12a62cbbff1df5edde17ff2d0915e67ca96948c3b3c6b10b0b7434e4ee4df61044209f7ca5e90d55850a10923da13401094f169664d71abd7be9a45d6badb0f6149787f41f59dbe63b404b42707c50945acc0fbcb038e93360267aa262db879f012226e13d6166957e68f39c44734e89cff073f123075b0497898670a5b1acb1dd1ccf3056172a7118ed0620ca500f4732bf5af750dc48e87ae1fd83db79d20a54bf55e64a0972a3fe486654490cb659c7192aaa052700f4c0976fb2e8f490696a360ed228915792b50714760a01c2ac972c6c0122d7de6c4ced550f61191b0f217f175f7c97eaa17612fc734f8a0b8a9cd9c922cb8afefc95d6f2af3dd4170bb8220edd56d9cf1e0459289b419b275b79329158e2e1b958f47a4b7db0156c17be05cbb174f6383481c3ed812973ae539b08173207adbc494584703be561263032e6af2bbbeca41e4bbfe22d87a38b111ce28aab5f3a10ea4232eaf6127f29143cb3de21b06f560371dc9d41f6cc5417f31b9d6aece3ca37c130a003bf2db9665dad94d927a11f95027f930c30c7885fc8c9af714da24a5574b31846711e5ed332982dbb96d48271a75e9a6a78f42884043a5f18b645d1129431006770edb82675335eb3280f5192655dd3d5f36c6243734e2d88aa77a81779140dbacca04b1211b113a1a78d34d619174c271e20af21bdcb75ba27e939908ac434d451a98db85bfd81250a1ec056b2a6cf0fe9a7b90559e0e8ea55d3fdc6df0bfc70b45f09e0e477621228e6982968d22d53eeb10b110b2045254c69ae84520e7cc9cdd50f94b1de42a2b0cf64d2f2d9ffecefea4d22dfe827e3463f5a3a14985a9d68943a85704ec8f6986e5febb60d3fd72c192407dff98c27c188d29279f34b4f14d80f9388091c5d2cc791163fa4f1a764878a699d6d9305d8e5bb24446ba5d6a6f14b7415d49943cee991fc43f884e81afd49f1dab3bcc3e94931c54ca59f6e4bfc1869232b0966771cec9c47d67de87d27784a2e787595e82d1f33df83a2e31887fbba326ba921aa4502bb770a1422202475e7505c27e4d9bb78145dd7bf04c43fe64e");
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00902248e30253b5b75d1dd8225b6ed31449ee978ff8ecf5711a2cefc2ca00d4"));
        assert(genesis.hashMerkleRoot == uint256S("0x93e6978040f4470ef080622dd45a446ff73d674b427b4126f29b09fe2d2df0f6"));

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("zclassic.org", "dnsseed.zclassic.org")); // zclassic
	    //vSeeds.push_back(CDNSSeedData("indieonion.org", "dnsseed.indieonion.org")); // @IndieOnion
        //vSeeds.push_back(CDNSSeedData("rotorproject.org", "dnsseed.rotorproject.org")); // @IndieOnion

        // guarantees the first 2 characters, when base58 encoded, are "t1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1C,0xB8};
        // guarantees the first 2 characters, when base58 encoded, are "t3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBD};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        /* TODO: AMI */ checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock),
            genesis.nTime,
            0,
            0
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
//          "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd", /* main-index: 0*/
//            "t3cL9AucCajm3HXDhb5jBnJK2vapVoXsop3", /* main-index: 1*/
//            "t3fqvkzrrNaMcamkQMwAyHRjfDdM2xQvDTR", /* main-index: 2*/
//            "t3TgZ9ZT2CTSK44AnUPi6qeNaHa2eC7pUyF", /* main-index: 3*/
//            "t3SpkcPQPfuRYHsP5vz3Pv86PgKo5m9KVmx", /* main-index: 4*/
//            "t3Xt4oQMRPagwbpQqkgAViQgtST4VoSWR6S", /* main-index: 5*/
//            "t3ayBkZ4w6kKXynwoHZFUSSgXRKtogTXNgb", /* main-index: 6*/
//            "t3adJBQuaa21u7NxbR8YMzp3km3TbSZ4MGB", /* main-index: 7*/
//            "t3K4aLYagSSBySdrfAGGeUd5H9z5Qvz88t2", /* main-index: 8*/
//            "t3RYnsc5nhEvKiva3ZPhfRSk7eyh1CrA6Rk", /* main-index: 9*/
//            "t3Ut4KUq2ZSMTPNE67pBU5LqYCi2q36KpXQ", /* main-index: 10*/
//            "t3ZnCNAvgu6CSyHm1vWtrx3aiN98dSAGpnD", /* main-index: 11*/
//            "t3fB9cB3eSYim64BS9xfwAHQUKLgQQroBDG", /* main-index: 12*/
//            "t3cwZfKNNj2vXMAHBQeewm6pXhKFdhk18kD", /* main-index: 13*/
//            "t3YcoujXfspWy7rbNUsGKxFEWZqNstGpeG4", /* main-index: 14*/
//            "t3bLvCLigc6rbNrUTS5NwkgyVrZcZumTRa4", /* main-index: 15*/
//            "t3VvHWa7r3oy67YtU4LZKGCWa2J6eGHvShi", /* main-index: 16*/
//            "t3eF9X6X2dSo7MCvTjfZEzwWrVzquxRLNeY", /* main-index: 17*/
//            "t3esCNwwmcyc8i9qQfyTbYhTqmYXZ9AwK3X", /* main-index: 18*/
//            "t3M4jN7hYE2e27yLsuQPPjuVek81WV3VbBj", /* main-index: 19*/
//            "t3gGWxdC67CYNoBbPjNvrrWLAWxPqZLxrVY", /* main-index: 20*/
//            "t3LTWeoxeWPbmdkUD3NWBquk4WkazhFBmvU", /* main-index: 21*/
//            "t3P5KKX97gXYFSaSjJPiruQEX84yF5z3Tjq", /* main-index: 22*/
//            "t3f3T3nCWsEpzmD35VK62JgQfFig74dV8C9", /* main-index: 23*/
//            "t3Rqonuzz7afkF7156ZA4vi4iimRSEn41hj", /* main-index: 24*/
//            "t3fJZ5jYsyxDtvNrWBeoMbvJaQCj4JJgbgX", /* main-index: 25*/
//            "t3Pnbg7XjP7FGPBUuz75H65aczphHgkpoJW", /* main-index: 26*/
//            "t3WeKQDxCijL5X7rwFem1MTL9ZwVJkUFhpF", /* main-index: 27*/
//            "t3Y9FNi26J7UtAUC4moaETLbMo8KS1Be6ME", /* main-index: 28*/
//            "t3aNRLLsL2y8xcjPheZZwFy3Pcv7CsTwBec", /* main-index: 29*/
//            "t3gQDEavk5VzAAHK8TrQu2BWDLxEiF1unBm", /* main-index: 30*/
//            "t3Rbykhx1TUFrgXrmBYrAJe2STxRKFL7G9r", /* main-index: 31*/
//            "t3aaW4aTdP7a8d1VTE1Bod2yhbeggHgMajR", /* main-index: 32*/
//            "t3YEiAa6uEjXwFL2v5ztU1fn3yKgzMQqNyo", /* main-index: 33*/
//            "t3g1yUUwt2PbmDvMDevTCPWUcbDatL2iQGP", /* main-index: 34*/
//            "t3dPWnep6YqGPuY1CecgbeZrY9iUwH8Yd4z", /* main-index: 35*/
//            "t3QRZXHDPh2hwU46iQs2776kRuuWfwFp4dV", /* main-index: 36*/
//            "t3enhACRxi1ZD7e8ePomVGKn7wp7N9fFJ3r", /* main-index: 37*/
//            "t3PkLgT71TnF112nSwBToXsD77yNbx2gJJY", /* main-index: 38*/
//            "t3LQtHUDoe7ZhhvddRv4vnaoNAhCr2f4oFN", /* main-index: 39*/
//            "t3fNcdBUbycvbCtsD2n9q3LuxG7jVPvFB8L", /* main-index: 40*/
//            "t3dKojUU2EMjs28nHV84TvkVEUDu1M1FaEx", /* main-index: 41*/
//            "t3aKH6NiWN1ofGd8c19rZiqgYpkJ3n679ME", /* main-index: 42*/
//            "t3MEXDF9Wsi63KwpPuQdD6by32Mw2bNTbEa", /* main-index: 43*/
//            "t3WDhPfik343yNmPTqtkZAoQZeqA83K7Y3f", /* main-index: 44*/
//            "t3PSn5TbMMAEw7Eu36DYctFezRzpX1hzf3M", /* main-index: 45*/
//            "t3R3Y5vnBLrEn8L6wFjPjBLnxSUQsKnmFpv", /* main-index: 46*/
//            "t3Pcm737EsVkGTbhsu2NekKtJeG92mvYyoN", /* main-index: 47*/
////            "t3PZ9PPcLzgL57XRSG5ND4WNBC9UTFb8DXv", /* main-index: 48*/
////            "t3L1WgcyQ95vtpSgjHfgANHyVYvffJZ9iGb", /* main-index: 49*/
////            "t3JtoXqsv3FuS7SznYCd5pZJGU9di15mdd7", /* main-index: 50*/
////            "t3hLJHrHs3ytDgExxr1mD8DYSrk1TowGV25", /* main-index: 51*/
////            "t3fmYHU2DnVaQgPhDs6TMFVmyC3qbWEWgXN", /* main-index: 52*/
////            "t3T4WmAp6nrLkJ24iPpGeCe1fSWTPv47ASG", /* main-index: 53*/
////            "t3fP6GrDM4QVwdjFhmCxGNbe7jXXXSDQ5dv", /* main-index: 54*/
};
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "AMT";
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.fPowAllowMinDifficultyBlocks = true;
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        /* TODO: create AMI key */ vAlertPubKey = ParseHex("048679fb891b15d0cada9692047fd0ae26ad8bfb83fabddbb50334ee5bc0683294deb410be20513c5af6e7b9cec717ade82b27080ee6ef9a245c36a795ab044bb3");
        nDefaultPort = 18199; // 18233 - 100 + 66
        nMinerThreads = 0;
        nPruneAfterHeight = 1000;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1494680115;  // TODO: Change start date
        genesis.nBits = 0x2007ffff;
        genesis.nNonce = uint256S("0x0000000000000000000000000000000000000000000000000000000000000222");
        genesis.nSolution = ParseHex("0019f7206640383834adf15a693edde50ebbebaf8d1ed526ad628c918f795dc2a3cae776f0c1a62e089d048ede10289caad59013231366c8a2e375585ecc263f1f14b458dc37a79f8c246c3365a38a447dbbef5e01b490c207442841055a2095fe94ff60a9cc5655f713cb25e2740ffe05536aa292bf355aa120efb652d424cd1eb2a4b4400dbc03954c4c30fbaa1adf946a0b28a95658815bb3a752bcd2d732ffc331fc06db948600d511b807c7a978961a93215d557fba57e1393c711685b23f24e07eff1fc80301a2411e5dca8176a2da0883dd30a99ff4c97c5d020aa09a3da9f1947491fe61998351d0f9244fcb50fbadee6656c32fea5b5f1b01924c734af6f21feb33433e781ad07e6289babe85128dc2f76146a60103f0b30cefa6234a633b980ced04c416ac8f8787ac8d17167957bf3f42a9869991f51895b1750b9ff00bdd6123df974884f676cd7ce3b50338eba3a95c04232718c2a06c1b4585e1ef7a8e6b0fc043a76b2a8107d88396a83458f19212761102d811ceb2b2317295f1e3728328a9770f02b533f7c5c119a47d584476e2a5dbc0d2e5902ead5f05ca1f3d8421ea4ac9c591e6f2a2be53d30eaf9302a24b5cddb02ba44481f4d53fad86e585048dcbff2a43d1b9db8528d84e9479a60d8d5a3074b359391bb614d113358e3889c1e5ac2e5fd9f6e9b3e83dbcb0ff81fc1c914408d7e7b11dee32a39ce9a33114dcedffabd05da45e369a9d94c4f9c9dfcec88374b0f2a6ee8cad1af90b10b86dad4b5ab5dafc763335ad6712511eba163dae59a1a6a4d1e5298d4b12a62cbbff1df5edde17ff2d0915e67ca96948c3b3c6b10b0b7434e4ee4df61044209f7ca5e90d55850a10923da13401094f169664d71abd7be9a45d6badb0f6149787f41f59dbe63b404b42707c50945acc0fbcb038e93360267aa262db879f012226e13d6166957e68f39c44734e89cff073f123075b0497898670a5b1acb1dd1ccf3056172a7118ed0620ca500f4732bf5af750dc48e87ae1fd83db79d20a54bf55e64a0972a3fe486654490cb659c7192aaa052700f4c0976fb2e8f490696a360ed228915792b50714760a01c2ac972c6c0122d7de6c4ced550f61191b0f217f175f7c97eaa17612fc734f8a0b8a9cd9c922cb8afefc95d6f2af3dd4170bb8220edd56d9cf1e0459289b419b275b79329158e2e1b958f47a4b7db0156c17be05cbb174f6383481c3ed812973ae539b08173207adbc494584703be561263032e6af2bbbeca41e4bbfe22d87a38b111ce28aab5f3a10ea4232eaf6127f29143cb3de21b06f560371dc9d41f6cc5417f31b9d6aece3ca37c130a003bf2db9665dad94d927a11f95027f930c30c7885fc8c9af714da24a5574b31846711e5ed332982dbb96d48271a75e9a6a78f42884043a5f18b645d1129431006770edb82675335eb3280f5192655dd3d5f36c6243734e2d88aa77a81779140dbacca04b1211b113a1a78d34d619174c271e20af21bdcb75ba27e939908ac434d451a98db85bfd81250a1ec056b2a6cf0fe9a7b90559e0e8ea55d3fdc6df0bfc70b45f09e0e477621228e6982968d22d53eeb10b110b2045254c69ae84520e7cc9cdd50f94b1de42a2b0cf64d2f2d9ffecefea4d22dfe827e3463f5a3a14985a9d68943a85704ec8f6986e5febb60d3fd72c192407dff98c27c188d29279f34b4f14d80f9388091c5d2cc791163fa4f1a764878a699d6d9305d8e5bb24446ba5d6a6f14b7415d49943cee991fc43f884e81afd49f1dab3bcc3e94931c54ca59f6e4bfc1869232b0966771cec9c47d67de87d27784a2e787595e82d1f33df83a2e31887fbba326ba921aa4502bb770a1422202475e7505c27e4d9bb78145dd7bf04c43fe64e");
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00902248e30253b5b75d1dd8225b6ed31449ee978ff8ecf5711a2cefc2ca00d4"));

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("rotorproject.org", "test-dnsseed.rotorproject.org")); // Zclassic

        // guarantees the first 2 characters, when base58 encoded, are "tm"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "t2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock),
            genesis.nTime,
            0,
            0
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
	/*
            "t2UNzUUx8mWBCRYPRezvA363EYXyEpHokyi", "t2N9PH9Wk9xjqYg9iin1Ua3aekJqfAtE543", "t2NGQjYMQhFndDHguvUw4wZdNdsssA6K7x2", "t27ktmq1kbeCWiQ5TZ7w5npSzcdbBmTB7v6",
            "t2GcBttAKD2WTHka8HyGc2dfvVTKYZUfHmJ", "t2Q3vxWaD9LrdqUE8Xd9Ddjpr9pUQ2aGotK", "t2TTfWDsYu998fHWzVP9Gns4fgxXXRi1Wzu", "t2KS6R4MMWdSBMjLCiw2iMyhWGRQPmyRqDn",
            "t2Q2ELrgotWv3Eec6LEtMMiiQ8dtW38u8Tj", "t2AEgJA88vTWAKqxJDFUEJWyHUtQAZi5G1D", "t2HCSdmpq1TQKksuwPQevwAzPTgfJ2rkMbG", "t2HQCPFAUQaUdJWHPhg5pPBxit7inaJzubE",
            "t2Fzqvq8Y9e6Mn3JNPb982aYsLmq4b5HmhH", "t2HEz7YZQqDUgC5h4y2WSD3mWneqJNVRjjJ", "t2GCR1SCk687Eeo5NEZ23MLsms7JjVWBgfG", "t2KyiPR9Lztq2w1w747X6W4nkUMAGL8M9KN",
            "t2UxymadyxSyVihmbq7S1yxw5dCBqJ1S4jT", "t2AVeMy7fdmTcJhckqiKRG8B7F1vccEhSqU", "t26m7LwihQzD2sH7ZVhYpPJM5j7kzwbfKW9", "t2DgwUNTe7NxuyPU6fxsB5xJXap3E4yWXrN",
            "t2U6funcXA11fC9SZehyvUL3rk3Vhuh7fzS", "t284JhyS8LGM72Tx1porSqwrcq3CejthP1p", "t29egu8QcpzKeLoPLqWS6QVMnUUPQdF6eNm", "t29LqD9p9D3B26euBwFi6mfcWu8HPA38VNs",
            "t28GsAMCxAyLy85XaasddDzaYFTtfewr86y", "t2GV44QyaikQPLUfm6oTfZnw71LLjnR7gDG", "t2U2QzNLQ1jtAu4L6xxVnRXLBsQpQvGRR2g", "t2QKGr5PNan7nrwDgseyHMN9NFeeuUjCh8b",
            "t2AfS8u6HwBeJpKpbuxztvRjupKQDXqnrwa", "t2CTRQUViQd3CWMhnKhFnUHqDLUyTxmWhJs", "t2CbM9EqszNURqh1UXZBXYhwp1R4GwEhWRE", "t2LM7uYiAsKDU42GNSnMwDxbZ8s1DowQzYH",
            "t2AgvT35LHR378AE3ouz6xKMhkTLHLJC6nD", "t285EAQXUVyi4NMddJv2QqTrnv45GRMbP8e", "t2EpMRCD5b8f2DCQ37npNULcpZhkjC8muqA", "t2BCmWXrRPiCeQTpizSWKKRPM5X6PS7umDY",
            "t2DN7X6wDFn5hYKBiBmn3Z98st419yaTVTH", "t2QJj8HeCwQ6mHwqekxxDLZntYpZTHNU62t", "t2QdHBR1Yciqn4j8gpS8DcQZZtYetKvfNj3", "t2E5cpLA1ey5VNxFNcuopeQMq2rH2NHiPdu",
            "t2EVRGtzjFAyz8CF8ndvLuiJu7qZUfDa93H", "t2KoQDk3BSFadBkuaWdLwchFuQamzw9RE4L", "t2FnR3yhTmuiejEJeu6qpidWTghRd1HpjLt", "t2BAuBAAospDc9d1u5nNGEi6x4NRJBD2PQ2",
            "t2RtKrLCGcyPkm4a4APg1YY9Wu2m4R2PgrB", "t28aUbSteZzBq2pFgj1K1XNZRZP5mMMyakV", "t2Urdy1ERfkvsFuy6Z4BkhvYGzWdmivfAFR", "t2ADinR4JrvCMd4Q1XGALPajzFrirqvhED6",
	*/
        };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nMinerThreads = 1;
        nMaxTipAge = 24 * 60 * 60;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        genesis.nTime = 1494680115;  // TODO: Change start date
        genesis.nBits = 0x2007ffff;
        genesis.nNonce = uint256S("0x0000000000000000000000000000000000000000000000000000000000000222");
        genesis.nSolution = ParseHex("0019f7206640383834adf15a693edde50ebbebaf8d1ed526ad628c918f795dc2a3cae776f0c1a62e089d048ede10289caad59013231366c8a2e375585ecc263f1f14b458dc37a79f8c246c3365a38a447dbbef5e01b490c207442841055a2095fe94ff60a9cc5655f713cb25e2740ffe05536aa292bf355aa120efb652d424cd1eb2a4b4400dbc03954c4c30fbaa1adf946a0b28a95658815bb3a752bcd2d732ffc331fc06db948600d511b807c7a978961a93215d557fba57e1393c711685b23f24e07eff1fc80301a2411e5dca8176a2da0883dd30a99ff4c97c5d020aa09a3da9f1947491fe61998351d0f9244fcb50fbadee6656c32fea5b5f1b01924c734af6f21feb33433e781ad07e6289babe85128dc2f76146a60103f0b30cefa6234a633b980ced04c416ac8f8787ac8d17167957bf3f42a9869991f51895b1750b9ff00bdd6123df974884f676cd7ce3b50338eba3a95c04232718c2a06c1b4585e1ef7a8e6b0fc043a76b2a8107d88396a83458f19212761102d811ceb2b2317295f1e3728328a9770f02b533f7c5c119a47d584476e2a5dbc0d2e5902ead5f05ca1f3d8421ea4ac9c591e6f2a2be53d30eaf9302a24b5cddb02ba44481f4d53fad86e585048dcbff2a43d1b9db8528d84e9479a60d8d5a3074b359391bb614d113358e3889c1e5ac2e5fd9f6e9b3e83dbcb0ff81fc1c914408d7e7b11dee32a39ce9a33114dcedffabd05da45e369a9d94c4f9c9dfcec88374b0f2a6ee8cad1af90b10b86dad4b5ab5dafc763335ad6712511eba163dae59a1a6a4d1e5298d4b12a62cbbff1df5edde17ff2d0915e67ca96948c3b3c6b10b0b7434e4ee4df61044209f7ca5e90d55850a10923da13401094f169664d71abd7be9a45d6badb0f6149787f41f59dbe63b404b42707c50945acc0fbcb038e93360267aa262db879f012226e13d6166957e68f39c44734e89cff073f123075b0497898670a5b1acb1dd1ccf3056172a7118ed0620ca500f4732bf5af750dc48e87ae1fd83db79d20a54bf55e64a0972a3fe486654490cb659c7192aaa052700f4c0976fb2e8f490696a360ed228915792b50714760a01c2ac972c6c0122d7de6c4ced550f61191b0f217f175f7c97eaa17612fc734f8a0b8a9cd9c922cb8afefc95d6f2af3dd4170bb8220edd56d9cf1e0459289b419b275b79329158e2e1b958f47a4b7db0156c17be05cbb174f6383481c3ed812973ae539b08173207adbc494584703be561263032e6af2bbbeca41e4bbfe22d87a38b111ce28aab5f3a10ea4232eaf6127f29143cb3de21b06f560371dc9d41f6cc5417f31b9d6aece3ca37c130a003bf2db9665dad94d927a11f95027f930c30c7885fc8c9af714da24a5574b31846711e5ed332982dbb96d48271a75e9a6a78f42884043a5f18b645d1129431006770edb82675335eb3280f5192655dd3d5f36c6243734e2d88aa77a81779140dbacca04b1211b113a1a78d34d619174c271e20af21bdcb75ba27e939908ac434d451a98db85bfd81250a1ec056b2a6cf0fe9a7b90559e0e8ea55d3fdc6df0bfc70b45f09e0e477621228e6982968d22d53eeb10b110b2045254c69ae84520e7cc9cdd50f94b1de42a2b0cf64d2f2d9ffecefea4d22dfe827e3463f5a3a14985a9d68943a85704ec8f6986e5febb60d3fd72c192407dff98c27c188d29279f34b4f14d80f9388091c5d2cc791163fa4f1a764878a699d6d9305d8e5bb24446ba5d6a6f14b7415d49943cee991fc43f884e81afd49f1dab3bcc3e94931c54ca59f6e4bfc1869232b0966771cec9c47d67de87d27784a2e787595e82d1f33df83a2e31887fbba326ba921aa4502bb770a1422202475e7505c27e4d9bb78145dd7bf04c43fe64e");
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00902248e30253b5b75d1dd8225b6ed31449ee978ff8ecf5711a2cefc2ca00d4"));

        nDefaultPort = 18099; // 18133 - 100 + 66
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (Checkpoints::CCheckpointData){
            boost::assign::map_list_of
            /* TODO: AMI - see above */ ( 0, uint256S("0x0575f78ee8dc057deee78ef691876e3be29833aaee5e189bb0459c087451305a")),
            0,
            0,
            0
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        //vFoundersRewardAddress = { "t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg" };
	vFoundersRewardAddress = { };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CBitcoinAddress address(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(address.IsValid());
    assert(address.IsScript());
    CScriptID scriptID = get<CScriptID>(address.Get()); // Get() returns a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}
