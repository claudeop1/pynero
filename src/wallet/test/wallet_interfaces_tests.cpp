// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <interfaces/wallet.h>
#include <test/util/setup_common.h>
#include <util/bip32.h>
#include <wallet/context.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>
#include <optional>
#include <vector>

namespace wallet {

BOOST_FIXTURE_TEST_SUITE(wallet_interfaces_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(derivehdkey)
{
    WalletContext context;
    context.args = &m_args;
    auto wallet = TestCreateWallet(context);
    BOOST_REQUIRE(wallet);
    auto interface = interfaces::MakeWallet(context, wallet);

    std::vector<uint32_t> path{87 | BIP32_HARDENED_FLAG};
    auto result = interface->deriveHDKey(path, std::nullopt);
    BOOST_REQUIRE(result);
    BOOST_CHECK(result->first.pubkey.IsValid());
    BOOST_CHECK(result->second.path == path);
}

BOOST_AUTO_TEST_CASE(derivehdkey_unhardened_path)
{
    WalletContext context;
    context.args = &m_args;
    auto wallet = TestCreateWallet(context);
    BOOST_REQUIRE(wallet);
    auto interface = interfaces::MakeWallet(context, wallet);

    auto result = interface->deriveHDKey(/*path=*/{87}, std::nullopt);
    BOOST_REQUIRE(!result);
    BOOST_CHECK(result.error().code == WalletErrorCode::GenericError);
    BOOST_CHECK_EQUAL(result.error().message.original, "Derivation path requires at least one hardened step");
}

BOOST_AUTO_TEST_CASE(derivehdkey_path_too_deep)
{
    WalletContext context;
    context.args = &m_args;
    auto wallet = TestCreateWallet(context);
    BOOST_REQUIRE(wallet);
    auto interface = interfaces::MakeWallet(context, wallet);

    std::vector<uint32_t> path(256, BIP32_HARDENED_FLAG);
    auto result = interface->deriveHDKey(path, std::nullopt);
    BOOST_REQUIRE(!result);
    BOOST_CHECK(result.error().code == WalletErrorCode::GenericError);
    BOOST_CHECK_EQUAL(result.error().message.original, "Unable to derive HD key at the requested path");
}

BOOST_AUTO_TEST_CASE(derivehdkey_unknown_hdkey)
{
    WalletContext context;
    context.args = &m_args;
    auto wallet = TestCreateWallet(context);
    BOOST_REQUIRE(wallet);
    auto interface = interfaces::MakeWallet(context, wallet);

    CExtKey unknown;
    unknown.SetSeed(GenerateRandomKey());

    auto result = interface->deriveHDKey(/*path=*/{87 | BIP32_HARDENED_FLAG}, unknown.Neuter());
    BOOST_REQUIRE(!result);
    BOOST_CHECK(result.error().code == WalletErrorCode::GenericError);
    BOOST_CHECK_EQUAL(result.error().message.original, "HD key is not used by an active or unused(KEY) descriptor");
}

BOOST_AUTO_TEST_CASE(derivehdkey_watch_only_wallet)
{
    WalletContext context;
    context.args = &m_args;
    DatabaseOptions options;
    options.require_create = true;
    options.create_flags = WALLET_FLAG_DESCRIPTORS | WALLET_FLAG_DISABLE_PRIVATE_KEYS;
    DatabaseStatus status;
    bilingual_str error;
    auto wallet = TestCreateWallet(MakeWalletDatabase("", options, status, error), context, options.create_flags);
    BOOST_REQUIRE(wallet);
    auto interface = interfaces::MakeWallet(context, wallet);

    auto result = interface->deriveHDKey(/*path=*/{87 | BIP32_HARDENED_FLAG}, std::nullopt);
    BOOST_REQUIRE(!result);
    BOOST_CHECK(result.error().code == WalletErrorCode::GenericError);
    BOOST_CHECK_EQUAL(result.error().message.original, "Deriving HD keys is not available for watch-only wallets");
}

BOOST_AUTO_TEST_CASE(derivehdkey_wallet_locked)
{
    WalletContext context;
    context.args = &m_args;
    auto wallet = TestCreateWallet(context);
    BOOST_REQUIRE(wallet);
    BOOST_REQUIRE(wallet->EncryptWallet("hunter2"));
    BOOST_REQUIRE(wallet->Lock());

    auto interface = interfaces::MakeWallet(context, wallet);
    auto result = interface->deriveHDKey(/*path=*/{87 | BIP32_HARDENED_FLAG}, std::nullopt);
    BOOST_REQUIRE(!result);
    BOOST_CHECK(result.error().code == WalletErrorCode::UnlockNeeded);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
