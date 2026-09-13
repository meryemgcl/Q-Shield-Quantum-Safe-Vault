import unittest
import sys
from tests.test_kyber import test_kyber_keygen, test_kyber_encapsulation_decapsulation, test_kyber_different_keys_generate_different_secrets
from tests.test_dilithium import test_dilithium_keygen, test_dilithium_sign_and_verify, test_dilithium_tampered_message_fails, test_dilithium_tampered_signature_fails
from tests.test_protocol import test_pqc_handshake_and_messaging

class TestQShield(unittest.TestCase):
    def test_kyber_all(self):
        test_kyber_keygen()
        test_kyber_encapsulation_decapsulation()
        test_kyber_different_keys_generate_different_secrets()

    def test_dilithium_all(self):
        test_dilithium_keygen()
        test_dilithium_sign_and_verify()
        test_dilithium_tampered_message_fails()
        test_dilithium_tampered_signature_fails()

    def test_protocol_all(self):
        test_pqc_handshake_and_messaging()

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestQShield)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
