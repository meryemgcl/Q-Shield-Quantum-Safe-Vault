import unittest
import sys
import tempfile
from pathlib import Path

from tests.test_kyber import test_kyber_keygen, test_kyber_encapsulation_decapsulation, test_kyber_different_keys_generate_different_secrets
from tests.test_dilithium import test_dilithium_keygen, test_dilithium_sign_and_verify, test_dilithium_tampered_message_fails, test_dilithium_tampered_signature_fails
from tests.test_protocol import test_pqc_handshake_and_messaging, test_pqc_mitm_detection
from tests.test_key_at_rest import test_key_at_rest_roundtrip, test_key_at_rest_wrong_password_fails
from tests.test_fuzzing import test_fuzzing_corrupted_vault_file
from tests.test_kat import test_nist_deterministic_kat
from tests.test_sidechannel import test_constant_time_poly_mul_bounds

class TestQShieldSuite(unittest.TestCase):
    def test_01_kyber_primitives(self):
        test_kyber_keygen()
        test_kyber_encapsulation_decapsulation()
        test_kyber_different_keys_generate_different_secrets()

    def test_02_dilithium_signatures(self):
        test_dilithium_keygen()
        test_dilithium_sign_and_verify()
        test_dilithium_tampered_message_fails()
        test_dilithium_tampered_signature_fails()

    def test_03_protocol_and_mitm(self):
        test_pqc_handshake_and_messaging()
        test_pqc_mitm_detection()

    def test_04_key_at_rest_protection(self):
        test_key_at_rest_roundtrip()
        test_key_at_rest_wrong_password_fails()

    def test_06_fuzzing_integrity(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_fuzzing_corrupted_vault_file(Path(tmp_dir))

    def test_07_nist_kat_determinism(self):
        test_nist_deterministic_kat()

    def test_08_sidechannel_timing(self):
        test_constant_time_poly_mul_bounds()

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestQShieldSuite)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
