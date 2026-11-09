<?php
// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

/**
 * Tests for the BIP340 Schnorr verifier.
 *
 * @package    auth_nostr
 * @copyright  2026 Librería de Satoshi
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers     \auth_nostr\schnorr
 */

namespace auth_nostr;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Unit tests for {@see schnorr}.
 *
 * @package    auth_nostr
 * @copyright  2026 Librería de Satoshi
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(schnorr::class)]
final class schnorr_test extends \basic_testcase {
    /**
     * Official BIP340 test vectors (indices 0-14, the ones with a 32-byte
     * message, which is the only shape a Nostr event id can have).
     *
     * @param string $pubkeyhex 32-byte x-only public key, hex.
     * @param string $msghex    32-byte message, hex.
     * @param string $sighex    64-byte signature, hex.
     * @param bool   $expected  Expected verification result.
     */
    #[DataProvider('bip340_vectors_provider')]
    public function test_bip340_vectors(string $pubkeyhex, string $msghex, string $sighex, bool $expected): void {
        $this->assertSame($expected, schnorr::verify($pubkeyhex, $msghex, $sighex));
    }

    /**
     * BIP340 test vectors from https://github.com/bitcoin/bips (bip-0340/test-vectors.csv).
     *
     * Reads the official vectors (indices 0-14) from the CSV fixture, so the
     * data stays verbatim and easy to refresh from upstream.
     *
     * @return array[] Rows of [public key hex, message hex, signature hex, expected result].
     */
    public static function bip340_vectors_provider(): array {
        $rows = [];
        $file = fopen(__DIR__ . '/fixtures/bip340_test_vectors.csv', 'r');
        fgetcsv($file); // Skip the header row.
        while (($cols = fgetcsv($file)) !== false) {
            $cols = array_pad($cols, 8, '');
            $name = 'vector ' . $cols[0] . ($cols[7] !== '' ? ': ' . $cols[7] : '');
            $rows[$name] = [
                strtolower($cols[2]), // Public key.
                strtolower($cols[4]), // Message.
                strtolower($cols[5]), // Signature.
                $cols[6] === 'TRUE',
            ];
        }
        fclose($file);
        return $rows;
    }

    /**
     * Messages that are not exactly 32 bytes are rejected outright (Nostr
     * event ids are always 32-byte hex, cf. BIP340 vectors 15-18).
     */
    public function test_rejects_non_32_byte_message(): void {
        $pubkey = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
        $sig    = 'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f' .
            '382d2ce5ebeee8fdb2172f477df4900d310536c0';
        $this->assertFalse(schnorr::verify($pubkey, '0102', $sig));
    }

    /**
     * Malformed hex input is rejected instead of raising errors.
     */
    public function test_rejects_malformed_hex(): void {
        $pubkey = str_repeat('zz', 32);
        $msg    = str_repeat('00', 32);
        $sig    = str_repeat('00', 64);
        $this->assertFalse(schnorr::verify($pubkey, $msg, $sig));
    }
}
