#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the interaction between ping timeouts and block download."""

import time

from test_framework.messages import (
    CInv,
    MSG_BLOCK,
    MSG_WITNESS_FLAG,
    msg_getdata,
    msg_ping,
)
from test_framework.p2p import (
    NetworkThread,
    P2PInterface,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    mine_large_block,
)

from test_framework.wallet import MiniWallet

TIMEOUT_INTERVAL = 20 * 60
MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16
PING_NONCE = 1
# Number of blocks the peer asks for in a single getdata message, the maximum a peer
# would request at the same time. The total amount of data requested (~16 MB) needs to
# be larger than what the kernel is willing to buffer for a socket that nobody reads
# from - otherwise the node would get through the entire request and answer the ping in
# spite of the peer not reading.
NUM_GETDATA = MAX_BLOCKS_IN_TRANSIT_PER_PEER


class SlowPeer(P2PInterface):
    """A peer that counts the blocks it receives."""
    def __init__(self):
        super().__init__()
        self.blocks_received = 0

    def on_block(self, message):
        self.blocks_received += 1


class PingIBDTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # Make the node stop serving blocks as soon as the peer stops reading from
        # the socket, instead of buffering up to 1 MB of them.
        self.extra_args = [["-maxsendbuffer=1"]]

    def set_reading(self, peer, enabled):
        """Pause or resume reading from the peer's socket."""
        pause_or_resume = peer._transport.resume_reading if enabled else peer._transport.pause_reading
        NetworkThread.network_event_loop.call_soon_threadsafe(pause_or_resume)

    def bytes_sent(self, node, msg_type):
        return node.getpeerinfo()[0]["bytessent_per_msg"].get(msg_type, 0)

    def wait_for_send_stall(self, node):
        """Wait until the node can't make any progress sending blocks to its peer anymore."""
        previous_bytes = 0

        def stalled():
            nonlocal previous_bytes
            block_bytes, previous_bytes = previous_bytes, self.bytes_sent(node, "block")
            return block_bytes > 0 and block_bytes == previous_bytes
        self.wait_until(stalled, check_interval=1)

    def test_pong_delay_ibd(self):
        # Tests that we only serve pings after serving all outstanding block requests, which could make a peer
        # timeout our node for not answering with a pong, even though the reason is their own slowness in downloading blocks.
        self.log.info("Check that during IBD, a node answers a ping only after serving the blocks asked for before it.")
        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        self.log.info("Mine a large block that can be served to a peer over and over again")
        mine_large_block(self, self.wallet, node)
        block_hash = int(node.getbestblockhash(), 16)

        node.setmocktime(int(time.time()))
        # Don't use v2transport in this test, the unoptimized python ChaCha20
        # implementation would take a long time to decrypt the blocks that are served.
        peer = node.add_p2p_connection(SlowPeer(), supports_v2_p2p=False)
        # Answer the ping the node sends right after the handshake, so that it has no
        # ping of its own pending while the peer isn't reading from the socket.
        peer.wait_until(lambda: "ping" in peer.last_message)
        peer.sync_with_ping()
        pong_bytes = self.bytes_sent(node, "pong")

        self.log.info("Ask for a lot of blocks, send a ping and stop reading from the socket")
        self.set_reading(peer, False)
        peer.send_without_ping(msg_getdata([CInv(MSG_BLOCK | MSG_WITNESS_FLAG, block_hash)] * NUM_GETDATA))
        peer.send_without_ping(msg_ping(nonce=PING_NONCE))
        self.wait_for_send_stall(node)
        assert_equal(self.bytes_sent(node, "pong"), pong_bytes)

        self.log.info(f"Check that the ping is still unanswered {TIMEOUT_INTERVAL + 60}s later")
        # Since we don't answer the ping within the ping timeout interval, the peer would disconnect
        # us if they don't relax the ping timeout rules while requesting blocks.
        # Note that the reason for the stall is not us, but the slowness of the peer itself, so
        # they would disconnect a good and fast peer that is not at fault.
        node.bumpmocktime(TIMEOUT_INTERVAL + 60)
        assert_equal(self.bytes_sent(node, "pong"), pong_bytes)
        assert peer.is_connected

        self.log.info("Check that the pong only arrives after all requested blocks were sent")
        peer.last_message.pop("pong")
        self.set_reading(peer, True)
        peer.wait_until(lambda: "pong" in peer.last_message, timeout=120)
        assert_equal(peer.last_message["pong"].nonce, PING_NONCE)
        assert_equal(peer.blocks_received, NUM_GETDATA)

    def run_test(self):
        self.test_pong_delay_ibd()


if __name__ == '__main__':
    PingIBDTest(__file__).main()
