import os
import sys
import types
import unittest
from unittest import mock

import analyzer


class FakeCompletions:
    def __init__(self, response):
        self.response = response
        self.request = None

    def create(self, **kwargs):
        self.request = kwargs
        return self.response


def fake_openai_module(response):
    completions = FakeCompletions(response)
    client = types.SimpleNamespace(
        chat=types.SimpleNamespace(completions=completions),
    )
    module = types.SimpleNamespace(OpenAI=lambda: client)
    return module, completions


class OpenAIAnalyzerTests(unittest.TestCase):
    def test_gpt5_mini_uses_larger_budget_and_low_reasoning(self):
        response = types.SimpleNamespace(
            choices=[types.SimpleNamespace(
                message=types.SimpleNamespace(content="analysis"),
                finish_reason="stop",
            )],
            usage=None,
        )
        module, completions = fake_openai_module(response)

        with mock.patch.dict(sys.modules, {"openai": module}), \
                mock.patch.dict(os.environ, {
                    "OPENAI_API_KEY": "test",
                    "HARDEN_MODEL": "gpt-5-mini",
                }), \
                mock.patch.object(analyzer, "MAX_OUTPUT_TOKENS", 16384), \
                mock.patch.object(analyzer, "OPENAI_REASONING_EFFORT", "low"):
            result = analyzer.analyze_with_openai("report")

        self.assertEqual(result, "analysis")
        self.assertEqual(completions.request["max_completion_tokens"], 16384)
        self.assertEqual(completions.request["reasoning_effort"], "low")
        self.assertEqual(completions.request["messages"][0]["role"], "developer")

    def test_empty_visible_response_returns_analyzer_error(self):
        response = types.SimpleNamespace(
            choices=[types.SimpleNamespace(
                message=types.SimpleNamespace(content=None),
                finish_reason="length",
            )],
            usage=types.SimpleNamespace(
                completion_tokens_details=types.SimpleNamespace(reasoning_tokens=4096),
            ),
        )
        module, _ = fake_openai_module(response)

        with mock.patch.dict(sys.modules, {"openai": module}), \
                mock.patch.dict(os.environ, {
                    "OPENAI_API_KEY": "test",
                    "HARDEN_MODEL": "gpt-5-mini",
                }):
            result = analyzer.analyze_with_openai("report")

        self.assertTrue(result.startswith("[analyzer]"))
        self.assertIn("finish_reason=length", result)
        self.assertIn("reasoning_tokens=4096", result)


if __name__ == "__main__":
    unittest.main()
