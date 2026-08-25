// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>

#include <chainparams.h>
#include <key_io.h>
#include <outputtype.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <rpc/util.h>
#include <script/keyorigin.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/random.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <numeric>
#include <optional>
#include <string>
#include <vector>

void initialize_key()
{
    static ECC_Context ecc_context{};
    SelectParams(ChainType::REGTEST);
}

FUZZ_TARGET(key, .init = initialize_key)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    const CKey key = [&] {
        CKey k;
        k.Set(buffer.begin(), buffer.end(), true);
        return k;
    }();
    if (!key.IsValid()) {
        return;
    }

    {
        Assert(key.begin() + key.size() == key.end());
        Assert(key.IsCompressed());
        Assert(key.size() == 32);
        Assert(DecodeSecret(EncodeSecret(key)) == key);
    }

    {
        CKey invalid_key;
        Assert(!(invalid_key == key));
        Assert(!invalid_key.IsCompressed());
        Assert(!invalid_key.IsValid());
        Assert(invalid_key.size() == 0);
    }

    {
        CKey uncompressed_key;
        uncompressed_key.Set(buffer.begin(), buffer.end(), false);
        Assert(!(uncompressed_key == key));
        Assert(!uncompressed_key.IsCompressed());
        Assert(key.size() == 32);
        Assert(uncompressed_key.begin() + uncompressed_key.size() == uncompressed_key.end());
        Assert(uncompressed_key.IsValid());
    }

    {
        CKey copied_key;
        copied_key.Set(key.begin(), key.end(), key.IsCompressed());
        Assert(copied_key == key);
    }

    const uint256 random_uint256 = Hash(buffer);

    {
        CKey child_key;
        ChainCode child_chaincode;
        const bool ok = key.Derive(child_key, child_chaincode, 0, ChainCode{random_uint256});
        Assert(ok);
        Assert(child_key.IsValid());
        Assert(!(child_key == key));
        Assert(child_chaincode != random_uint256);
    }

    const CPubKey pubkey = key.GetPubKey();

    {
        Assert(pubkey.size() == 33);
        Assert(key.VerifyPubKey(pubkey));
        Assert(pubkey.GetHash() != random_uint256);
        Assert(pubkey.begin() + pubkey.size() == pubkey.end());
        Assert(pubkey.data() == pubkey.begin());
        Assert(pubkey.IsCompressed());
        Assert(pubkey.IsValid());
        Assert(pubkey.IsFullyValid());
        Assert(HexToPubKey(HexStr(pubkey)) == pubkey);
    }

    {
        DataStream data_stream{};
        pubkey.Serialize(data_stream);

        CPubKey pubkey_deserialized;
        pubkey_deserialized.Unserialize(data_stream);
        Assert(pubkey_deserialized == pubkey);
    }

    {
        const CScript tx_pubkey_script = GetScriptForRawPubKey(pubkey);
        Assert(!tx_pubkey_script.IsPayToScriptHash());
        Assert(!tx_pubkey_script.IsPayToWitnessScriptHash());
        Assert(!tx_pubkey_script.IsPushOnly());
        Assert(!tx_pubkey_script.IsUnspendable());
        Assert(tx_pubkey_script.HasValidOps());
        Assert(tx_pubkey_script.size() == 35);

        const CScript tx_multisig_script = GetScriptForMultisig(1, {pubkey});
        Assert(!tx_multisig_script.IsPayToScriptHash());
        Assert(!tx_multisig_script.IsPayToWitnessScriptHash());
        Assert(!tx_multisig_script.IsPushOnly());
        Assert(!tx_multisig_script.IsUnspendable());
        Assert(tx_multisig_script.HasValidOps());
        Assert(tx_multisig_script.size() == 37);

        FillableSigningProvider fillable_signing_provider;
        Assert(!IsSegWitOutput(fillable_signing_provider, tx_pubkey_script));
        Assert(!IsSegWitOutput(fillable_signing_provider, tx_multisig_script));
        Assert(fillable_signing_provider.GetKeys().size() == 0);
        Assert(!fillable_signing_provider.HaveKey(pubkey.GetID()));

        const bool ok_add_key = fillable_signing_provider.AddKey(key);
        Assert(ok_add_key);
        Assert(fillable_signing_provider.HaveKey(pubkey.GetID()));

        FillableSigningProvider fillable_signing_provider_pub;
        Assert(!fillable_signing_provider_pub.HaveKey(pubkey.GetID()));

        const bool ok_add_key_pubkey = fillable_signing_provider_pub.AddKeyPubKey(key, pubkey);
        Assert(ok_add_key_pubkey);
        Assert(fillable_signing_provider_pub.HaveKey(pubkey.GetID()));

        TxoutType which_type_tx_pubkey;
        const bool is_standard_tx_pubkey = IsStandard(tx_pubkey_script, which_type_tx_pubkey);
        Assert(is_standard_tx_pubkey);
        Assert(which_type_tx_pubkey == TxoutType::PUBKEY);

        TxoutType which_type_tx_multisig;
        const bool is_standard_tx_multisig = IsStandard(tx_multisig_script, which_type_tx_multisig);
        Assert(is_standard_tx_multisig);
        Assert(which_type_tx_multisig == TxoutType::MULTISIG);

        std::vector<std::vector<unsigned char>> v_solutions_ret_tx_pubkey;
        const TxoutType outtype_tx_pubkey = Solver(tx_pubkey_script, v_solutions_ret_tx_pubkey);
        Assert(outtype_tx_pubkey == TxoutType::PUBKEY);
        Assert(v_solutions_ret_tx_pubkey.size() == 1);
        Assert(v_solutions_ret_tx_pubkey[0].size() == 33);

        std::vector<std::vector<unsigned char>> v_solutions_ret_tx_multisig;
        const TxoutType outtype_tx_multisig = Solver(tx_multisig_script, v_solutions_ret_tx_multisig);
        Assert(outtype_tx_multisig == TxoutType::MULTISIG);
        Assert(v_solutions_ret_tx_multisig.size() == 3);
        Assert(v_solutions_ret_tx_multisig[0].size() == 1);
        Assert(v_solutions_ret_tx_multisig[1].size() == 33);
        Assert(v_solutions_ret_tx_multisig[2].size() == 1);

        OutputType output_type{};
        const CTxDestination tx_destination{PKHash{pubkey}};
        Assert(output_type == OutputType::LEGACY);
        Assert(IsValidDestination(tx_destination));
        Assert(PKHash{pubkey} == *std::get_if<PKHash>(&tx_destination));

        const CScript script_for_destination = GetScriptForDestination(tx_destination);
        Assert(script_for_destination.size() == 25);

        const std::string destination_address = EncodeDestination(tx_destination);
        Assert(DecodeDestination(destination_address) == tx_destination);

        CKeyID key_id = pubkey.GetID();
        Assert(!key_id.IsNull());
        Assert(key_id == CKeyID{key_id});
        Assert(key_id == GetKeyForDestination(fillable_signing_provider, tx_destination));

        CPubKey pubkey_out;
        const bool ok_get_pubkey = fillable_signing_provider.GetPubKey(key_id, pubkey_out);
        Assert(ok_get_pubkey);

        CKey key_out;
        const bool ok_get_key = fillable_signing_provider.GetKey(key_id, key_out);
        Assert(ok_get_key);
        Assert(fillable_signing_provider.GetKeys().size() == 1);
        Assert(fillable_signing_provider.HaveKey(key_id));

        KeyOriginInfo key_origin_info;
        const bool ok_get_key_origin = fillable_signing_provider.GetKeyOrigin(key_id, key_origin_info);
        Assert(!ok_get_key_origin);
    }

    {
        const std::vector<unsigned char> vch_pubkey{pubkey.begin(), pubkey.end()};
        Assert(CPubKey::ValidSize(vch_pubkey));
        Assert(!CPubKey::ValidSize({pubkey.begin(), pubkey.begin() + pubkey.size() - 1}));

        const CPubKey pubkey_ctor_1{vch_pubkey};
        Assert(pubkey == pubkey_ctor_1);

        const CPubKey pubkey_ctor_2{vch_pubkey.begin(), vch_pubkey.end()};
        Assert(pubkey == pubkey_ctor_2);

        CPubKey pubkey_set;
        pubkey_set.Set(vch_pubkey.begin(), vch_pubkey.end());
        Assert(pubkey == pubkey_set);
    }

    {
        const CPubKey invalid_pubkey{};
        Assert(!invalid_pubkey.IsValid());
        Assert(!invalid_pubkey.IsFullyValid());
        Assert(!(pubkey == invalid_pubkey));
        Assert(pubkey != invalid_pubkey);
        Assert(pubkey < invalid_pubkey);
    }

    {
        // Cover CPubKey's operator[](unsigned int pos)
        unsigned int sum = 0;
        for (size_t i = 0; i < pubkey.size(); ++i) {
            sum += pubkey[i];
        }
        Assert(std::accumulate(pubkey.begin(), pubkey.end(), 0U) == sum);
    }

    {
        CPubKey decompressed_pubkey = pubkey;
        Assert(decompressed_pubkey.IsCompressed());

        const bool ok = decompressed_pubkey.Decompress();
        Assert(ok);
        Assert(!decompressed_pubkey.IsCompressed());
        Assert(decompressed_pubkey.size() == 65);
    }

    {
        std::vector<unsigned char> vch_sig;
        const bool ok = key.Sign(random_uint256, vch_sig, false);
        Assert(ok);
        Assert(pubkey.Verify(random_uint256, vch_sig));
        Assert(CPubKey::CheckLowS(vch_sig));

        const std::vector<unsigned char> vch_invalid_sig{vch_sig.begin(), vch_sig.begin() + vch_sig.size() - 1};
        Assert(!pubkey.Verify(random_uint256, vch_invalid_sig));
        Assert(!CPubKey::CheckLowS(vch_invalid_sig));
    }

    {
        std::vector<unsigned char> vch_compact_sig;
        const bool ok_sign_compact = key.SignCompact(random_uint256, vch_compact_sig);
        Assert(ok_sign_compact);

        CPubKey recover_pubkey;
        const bool ok_recover_compact = recover_pubkey.RecoverCompact(random_uint256, vch_compact_sig);
        Assert(ok_recover_compact);
        Assert(recover_pubkey == pubkey);
    }

    {
        CPubKey child_pubkey;
        ChainCode child_chaincode;
        const bool ok = pubkey.Derive(child_pubkey, child_chaincode, 0, ChainCode{random_uint256});
        Assert(ok);
        Assert(child_pubkey != pubkey);
        Assert(child_pubkey.IsCompressed());
        Assert(child_pubkey.IsFullyValid());
        Assert(child_pubkey.IsValid());
        Assert(child_pubkey.size() == 33);
        Assert(child_chaincode != random_uint256);
    }

    const CPrivKey priv_key = key.GetPrivKey();

    {
        for (const bool skip_check : {true, false}) {
            CKey loaded_key;
            const bool ok = loaded_key.Load(priv_key, pubkey, skip_check);
            Assert(ok);
            Assert(key == loaded_key);
        }
    }
}

FUZZ_TARGET(ellswift_roundtrip, .init = initialize_key)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};

    CKey key = ConsumePrivateKey(fdp, /*compressed=*/true);
    if (!key.IsValid()) return;

    auto ent32 = fdp.ConsumeBytes<std::byte>(32);
    ent32.resize(32);

    auto encoded_ellswift = key.EllSwiftCreate(ent32);
    auto decoded_pubkey = encoded_ellswift.Decode();

    uint256 hash{ConsumeUInt256(fdp)};
    std::vector<unsigned char> sig;
    key.Sign(hash, sig);
    Assert(decoded_pubkey.Verify(hash, sig));
}

FUZZ_TARGET(bip324_ecdh, .init = initialize_key)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};

    // We generate private key, k1.
    CKey k1 = ConsumePrivateKey(fdp, /*compressed=*/true);
    if (!k1.IsValid()) return;

    // They generate private key, k2.
    CKey k2 = ConsumePrivateKey(fdp, /*compressed=*/true);
    if (!k2.IsValid()) return;

    // We construct an ellswift encoding for our key, k1_ellswift.
    auto ent32_1 = fdp.ConsumeBytes<std::byte>(32);
    ent32_1.resize(32);
    auto k1_ellswift = k1.EllSwiftCreate(ent32_1);

    // They construct an ellswift encoding for their key, k2_ellswift.
    auto ent32_2 = fdp.ConsumeBytes<std::byte>(32);
    ent32_2.resize(32);
    auto k2_ellswift = k2.EllSwiftCreate(ent32_2);

    // They construct another (possibly distinct) ellswift encoding for their key, k2_ellswift_bad.
    auto ent32_2_bad = fdp.ConsumeBytes<std::byte>(32);
    ent32_2_bad.resize(32);
    auto k2_ellswift_bad = k2.EllSwiftCreate(ent32_2_bad);
    Assert((ent32_2_bad == ent32_2) == (k2_ellswift_bad == k2_ellswift));

    // Determine who is who.
    bool initiating = fdp.ConsumeBool();

    // We compute our shared secret using our key and their public key.
    auto ecdh_secret_1 = k1.ComputeBIP324ECDHSecret(k2_ellswift, k1_ellswift, initiating);
    // They compute their shared secret using their key and our public key.
    auto ecdh_secret_2 = k2.ComputeBIP324ECDHSecret(k1_ellswift, k2_ellswift, !initiating);
    // Those must match, as everyone is behaving correctly.
    Assert(ecdh_secret_1 == ecdh_secret_2);

    if (k1_ellswift != k2_ellswift) {
        // Unless the two keys are exactly identical, acting as the wrong party breaks things.
        auto ecdh_secret_bad = k1.ComputeBIP324ECDHSecret(k2_ellswift, k1_ellswift, !initiating);
        Assert(ecdh_secret_bad != ecdh_secret_1);
    }

    if (k2_ellswift_bad != k2_ellswift) {
        // Unless both encodings created by them are identical, using the second one breaks things.
        auto ecdh_secret_bad = k1.ComputeBIP324ECDHSecret(k2_ellswift_bad, k1_ellswift, initiating);
        Assert(ecdh_secret_bad != ecdh_secret_1);
    }
}
