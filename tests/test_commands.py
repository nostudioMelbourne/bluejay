import contextlib
import io
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import bluejay.commands as commands


class CommandDispatchTests(unittest.TestCase):
    def run_command(self, command_line: str, chat_path: Path) -> tuple[bool, Path]:
        with contextlib.redirect_stdout(io.StringIO()):
            return commands.handle_command(command_line, chat_path)

    def test_no_arg_command_dispatches_from_table(self) -> None:
        original_handler = commands.NO_ARG_COMMANDS["/help"]
        handler = Mock()
        chat_path = Path("chats/current.jsonl")
        commands.NO_ARG_COMMANDS["/help"] = handler

        try:
            running, returned_path = self.run_command("/help extra", chat_path)
        finally:
            commands.NO_ARG_COMMANDS["/help"] = original_handler

        self.assertTrue(running)
        self.assertEqual(returned_path, chat_path)
        handler.assert_called_once_with()

    def test_arg_command_dispatches_from_table(self) -> None:
        original_handler = commands.ARG_COMMANDS["/scan"]
        handler = Mock()
        chat_path = Path("chats/current.jsonl")
        commands.ARG_COMMANDS["/scan"] = handler

        try:
            running, returned_path = self.run_command("/scan localhost quick", chat_path)
        finally:
            commands.ARG_COMMANDS["/scan"] = original_handler

        self.assertTrue(running)
        self.assertEqual(returned_path, chat_path)
        handler.assert_called_once_with(["localhost", "quick"])

    def test_newchat_updates_chat_path(self) -> None:
        chat_path = Path("chats/current.jsonl")
        new_path = Path("chats/new.jsonl")

        with patch.object(commands, "create_chat_path", return_value=new_path):
            running, returned_path = self.run_command("/newchat", chat_path)

        self.assertTrue(running)
        self.assertEqual(returned_path, new_path)

    def test_exit_stops_command_loop(self) -> None:
        chat_path = Path("chats/current.jsonl")
        running, returned_path = self.run_command("/exit", chat_path)

        self.assertFalse(running)
        self.assertEqual(returned_path, chat_path)


if __name__ == "__main__":
    unittest.main()
