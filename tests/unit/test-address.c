/*
 * Unit tests for Wojak Coin (WJK) address encoding
 * Tests Base58 decoding through address_to_txn()
 *
 * WJK address formats:
 *   P2PKH mainnet:  'W...'   version byte 0x49 (73)
 *   P2SH  mainnet:  '3...'   version byte 0x05 (5)   -- same as Bitcoin
 *   P2PKH testnet:  'm.../n...' version byte 0x6F (111) -- same as Bitcoin testnet
 *   P2SH  testnet:  '2...'   version byte 0xC4 (196) -- same as Bitcoin testnet
 *
 * No segwit/bech32 — WJK does not support segwit.
 *
 * Note: address_to_txn() does not validate the address via RPC; it only
 * decodes the encoding (Base58) and builds the output script.
 * Full address validation happens via wojakcoind validateaddress RPC in
 * bitcoin.c:validate_address().
 */

/* config.h must be first to define _GNU_SOURCE before system headers */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../test_common.h"
#include "libckpool.h"

/*
 * P2PKH output script template (25 bytes):
 *   OP_DUP OP_HASH160 OP_PUSH20 <hash160[20]> OP_EQUALVERIFY OP_CHECKSIG
 *   0x76   0xa9       0x14                     0x88            0xac
 *
 * address_to_txn with script=false,segwit=false calls address_to_pubkeytxn()
 * which decodes the Base58Check address via b58tobin() and constructs this
 * script. b58tobin() is coin-agnostic; the version byte is stripped and the
 * remaining 20 bytes become the hash160. The WJK mainnet version byte (0x49)
 * is NOT written into the script — only the hash160 matters.
 *
 * We use the BTC genesis address here since b58tobin is coin-agnostic and
 * produces the same script structure for any valid Base58Check address.
 */
static void test_p2pkh_script_opcodes(void)
{
	char txn[100];
	int len;

	const char *addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
	len = address_to_txn(txn, addr, false, false);

	assert_true(len == 25);

	assert_true((unsigned char)txn[0] == 0x76); /* OP_DUP */
	assert_true((unsigned char)txn[1] == 0xa9); /* OP_HASH160 */
	assert_true((unsigned char)txn[2] == 0x14); /* push 20 bytes */
	assert_true((unsigned char)txn[23] == 0x88); /* OP_EQUALVERIFY */
	assert_true((unsigned char)txn[24] == 0xac); /* OP_CHECKSIG */
}

/*
 * P2SH output script template (23 bytes):
 *   OP_HASH160 OP_PUSH20 <hash160[20]> OP_EQUAL
 *   0xa9       0x14                    0x87
 *
 * WJK P2SH mainnet addresses start with '3' (version byte 0x05, same as Bitcoin).
 */
static void test_p2sh_script_opcodes(void)
{
	char txn[100];
	int len;

	const char *addr = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
	len = address_to_txn(txn, addr, true, false);

	assert_true(len == 23);

	assert_true((unsigned char)txn[0] == 0xa9); /* OP_HASH160 */
	assert_true((unsigned char)txn[1] == 0x14); /* push 20 bytes */
	assert_true((unsigned char)txn[22] == 0x87); /* OP_EQUAL */
}

int main(void)
{
	printf("Running WJK address encoding tests...\n\n");

	run_test(test_p2pkh_script_opcodes);
	run_test(test_p2sh_script_opcodes);

	printf("\nAll WJK address encoding tests passed!\n");
	return 0;
}
