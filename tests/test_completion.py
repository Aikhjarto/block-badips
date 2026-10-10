"""Tests for the bash completions in completions/."""
import os
import re
import shutil
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PLUGIN = os.path.join(ROOT, "usr", "lib", "nagios", "plugins", "check_block-badips.sh")
COMPLETIONS = os.path.join(ROOT, "completions")


def complete(command, *words):
    """The candidates bash offers for the last of words, which may be empty."""
    words = (command,) + words
    script = 'source "$1"; shift; COMP_WORDS=("$@"); COMP_CWORD=$(($# - 1)); ' \
             '$(complete -p "$1" | sed -E "s/.*-F ([^ ]+) .*/\\1/"); printf "%s\\n" "${COMPREPLY[@]}"'
    result = subprocess.run(["bash", "-c", script, "bash", os.path.join(COMPLETIONS, command)] + list(words),
                            capture_output=True, text=True, check=True)
    return [line for line in result.stdout.split("\n") if line]


def help_options():
    """The options -h of the plugin lists; it exits with UNKNOWN."""
    text = subprocess.run(["bash", PLUGIN, "-h"], capture_output=True, text=True).stdout
    return set(re.findall(r"^\s{2}(-\w)\s", text, re.MULTILINE))


@unittest.skipUnless(shutil.which("bash"), "bash is not installed")
class CompletionTests(unittest.TestCase):
    def test_syntax(self):
        for name in os.listdir(COMPLETIONS):
            subprocess.run(["bash", "-n", os.path.join(COMPLETIONS, name)], check=True)

    def test_plugin_offers_exactly_the_options_of_help(self):
        self.assertEqual(set(complete("check_block-badips.sh", "")), help_options())

    def test_plugin_option_prefix(self):
        self.assertEqual(complete("check_block-badips.sh", "-W"), ["-W"])

    def test_plugin_no_candidates_for_values(self):
        for option in ("-w", "-c", "-W", "-C", "-f"):
            self.assertEqual(complete("check_block-badips.sh", option, ""), [], option)

    def test_script_takes_no_arguments(self):
        self.assertEqual(complete("block-badips.sh", ""), [])


if __name__ == "__main__":
    unittest.main()
