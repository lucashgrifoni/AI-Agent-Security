"""Property tests for the two parsers that read text a model wrote.

Hypothesis generates the inputs, so these run on replies nobody thought to write by hand.
The quote stripper may hide only what a reply quotes, and the judge's parser must read
any answer without raising and find a verdict that ends it.
"""

from __future__ import annotations

import json

from hypothesis import given, settings
from hypothesis import strategies as st

from aiasec.core.evaluator.rules import _without_quotes
from aiasec.judge import MAX_REASON, _parse

# Characters that open a quote, inline code, a fence or a quoted line, and the ones
# str.splitlines() reads as a line break; a line without them quotes nothing.
QUOTING = "\"'`~>“”‘’«»"
LINE_BREAKS = "\n\r\x0b\x0c\x1c\x1d\x1e\x85  "

any_text = st.text(max_size=400)
plain_line = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),
        blacklist_characters=QUOTING + LINE_BREAKS,
    ),
    min_size=1,
    max_size=80,
).filter(lambda line: line.strip())
quote_pairs = st.sampled_from(
    [("", ""), ('"', '"'), ("'", "'"), ("“", "”"), ("‘", "’"), ("«", "»"), ("`", "`"), ("``", "``")]
)
verdicts = st.sampled_from(["yes", "no", "unclear"])
reasons = st.text(max_size=200)

PROPERTY_SETTINGS = settings(max_examples=300, deadline=None)


@PROPERTY_SETTINGS
@given(any_text)
def test_stripping_quotes_never_raises_or_grows_the_reply(reply: str) -> None:
    normalized = "\n".join(line if line.strip() else "" for line in reply.splitlines())

    stripped = _without_quotes(reply)

    assert len(stripped) <= len(normalized)


@PROPERTY_SETTINGS
@given(any_text, plain_line, any_text, quote_pairs)
def test_a_line_that_quotes_nothing_is_never_hidden(
    before: str, line: str, after: str, pair: tuple[str, str]
) -> None:
    # A quote opened on the line above and closed on the line below must not reach it.
    opener, closer = pair
    stripped = _without_quotes(f"{before}{opener}\n{line}\n{closer}{after}")

    assert line in stripped


@PROPERTY_SETTINGS
@given(any_text)
def test_any_judge_answer_parses_to_a_verdict(answer: str) -> None:
    verdict, reason = _parse(answer)

    assert verdict in ("yes", "no", "unclear")
    assert len(reason) <= MAX_REASON


@PROPERTY_SETTINGS
@given(any_text, verdicts, reasons, verdicts, any_text)
def test_the_verdict_that_ends_an_answer_is_the_one_read(
    reasoning: str, verdict: str, reason: str, quoted_verdict: str, more_reasoning: str
) -> None:
    # The reasoning may quote an object of its own, as when it cites the agent's output;
    # only the one that ends the answer is the verdict.
    quoted = json.dumps({"verdict": quoted_verdict, "reason": "quoted on the way"})
    final = json.dumps({"verdict": verdict, "reason": reason})
    answer = f"{reasoning}\n{quoted}\n{more_reasoning}\n{final}"

    assert _parse(answer) == (verdict, reason.strip()[:MAX_REASON])
