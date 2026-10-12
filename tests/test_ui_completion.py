import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from bluejay import ui


class ReadlineCompletionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.history_file = Path(self.temp_dir.name) / "data" / "history.txt"
        self.readline = Mock()
        self.readline.__doc__ = "GNU readline"
        self.readline.get_completer_delims.return_value = " \t\n/;"
        self.readline.get_begidx.return_value = 0
        self.readline.get_line_buffer.return_value = "/sta"

    def setup_completion(self):
        with (
            patch.dict("sys.modules", {"readline": self.readline}),
            patch.object(ui, "HISTORY_FILE", self.history_file),
            patch.object(ui.atexit, "register"),
        ):
            ui.setup_readline()
        return self.readline.set_completer.call_args.args[0]

    def test_tab_binding_supports_gnu_readline(self) -> None:
        self.setup_completion()
        self.readline.parse_and_bind.assert_called_once_with("tab: complete")

    def test_tab_binding_supports_macos_libedit(self) -> None:
        self.readline.__doc__ = "Command line editing using libedit readline."
        self.setup_completion()
        self.readline.parse_and_bind.assert_called_once_with("bind ^I rl_complete")

    def test_slash_is_part_of_the_completion_word(self) -> None:
        self.setup_completion()
        delimiters = self.readline.set_completer_delims.call_args.args[0]
        self.assertNotIn("/", delimiters)
        self.assertIn(" ", delimiters)
        self.assertIn("\t", delimiters)
        self.assertIn(";", delimiters)

    def test_partial_command_completes_and_exhausts_matches(self) -> None:
        complete = self.setup_completion()
        self.assertEqual(complete("/sta", 0), "/status")
        self.assertIsNone(complete("/sta", 1))
        self.assertIsNone(complete("/unknown", 0))

    def test_ambiguous_prefix_returns_each_matching_command(self) -> None:
        complete = self.setup_completion()
        self.assertEqual(complete("/s", 0), "/status")
        self.assertEqual(complete("/s", 1), "/scan")
        self.assertEqual(complete("/s", 2), "/site")
        self.assertIsNone(complete("/s", 3))

    def test_command_arguments_are_not_completed_as_commands(self) -> None:
        complete = self.setup_completion()
        self.readline.get_line_buffer.return_value = "/scan /sta"
        self.readline.get_begidx.return_value = len("/scan ")
        self.assertIsNone(complete("/sta", 0))

    def test_chat_text_has_no_command_completions(self) -> None:
        complete = self.setup_completion()
        self.readline.get_line_buffer.return_value = "hello"
        self.assertIsNone(complete("hello", 0))


if __name__ == "__main__":
    unittest.main()
