import unittest
from main2 import PasswordManager

class TestPasswordSecurity(unittest.TestCase):

    def setUp(self):
        self.manager = PasswordManager()
    
    def test_length(self):
        self.assertFalse(self.manager.password_strength("deepak"))
        self.assertTrue(self.manager.password_strength("deepak@3F"))

    def test_uppercase(self):
        self.assertTrue(self.manager.password_strength("deepak*2A"))
        self.assertFalse(self.manager.password_strength("deepak2&"))

    def test_lowercase(self):
        self.assertTrue(self.manager.password_strength("DEEPAK2@s"))
        self.assertFalse(self.manager.password_strength("DEEPAK2#"))

    def test_simble(self):
        self.assertTrue(self.manager.password_strength("DEEPAK2*s"))
        self.assertTrue(self.manager.password_strength("DEEPAK2$s"))
        self.assertTrue(self.manager.password_strength("DEEPAK2@s"))
        self.assertFalse(self.manager.password_strength("DEEPAK2s"))
        self.assertFalse(self.manager.password_strength("DEePak3333s"))

class TestPasswordGeneration(unittest.TestCase):
    def setUp(self):
        self.manager = PasswordManager()

    def test_length_randomness(self):
        """check if generated passwords are of arbitrary length"""
        passwords_length = [len(self.manager.generate_random_pass()) for i in range(10)]
        # check if any passwords contains duplicate
        self.assertNotEqual(1, len(set(passwords_length)))

    def test_randomness(self):
        """check if generated passwords are random"""
        passwords = [self.manager.generate_random_pass() for i in range(10)]
        # check if any passwords contains duplicate
        self.assertEqual(len(passwords), len(set(passwords)))


if __name__ == "__main__":
    unittest.main()