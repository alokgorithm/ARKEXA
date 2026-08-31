import unittest

from support import SRC  # noqa: F401  (puts src on the path)

from arkexa.loader import load_yaml


class LoaderTest(unittest.TestCase):
    def test_on_is_not_a_boolean(self):
        """YAML 1.1 turns `on:` into True. GitHub does not, so neither do we."""
        data = load_yaml("on:\n  issues:\n")
        self.assertIn("on", data)
        self.assertNotIn(True, data)

    def test_yes_and_no_stay_strings(self):
        data = load_yaml("a: yes\nb: no\n")
        self.assertEqual(data["a"], "yes")
        self.assertEqual(data["b"], "no")

    def test_true_and_false_are_booleans(self):
        data = load_yaml("a: true\nb: false\n")
        self.assertIs(data["a"], True)
        self.assertIs(data["b"], False)

    def test_keys_remember_their_line(self):
        data = load_yaml("name: x\non:\n  push:\njobs:\n  go: {}\n")
        self.assertEqual(data.key_line("name"), 1)
        self.assertEqual(data.key_line("on"), 2)
        self.assertEqual(data.key_line("jobs"), 4)

    def test_scalars_remember_their_line(self):
        data = load_yaml("a: one\nb: two\n")
        self.assertEqual(data["b"].line, 2)


if __name__ == "__main__":
    unittest.main()
