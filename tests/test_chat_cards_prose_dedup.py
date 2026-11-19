"""Regression cover for the next-steps prose/cards duplication: when a chat turn shows next-step
cards, any prose restatement of that same menu must be stripped from the visible reply so the
operator never sees the list twice (cards above a redundant numbered list). Exercises the pure
_strip_duplicated_next_steps helper directly, since that is where the conservative strip lives."""

from agent.chat import _strip_duplicated_next_steps


def test_strips_heading_and_list_keeping_surrounding_paragraphs():
    text = (
        "The license check hashes the input and compares it to a constant.\n\n"
        "Next Technical Threads:\n"
        "1. Decompile the compare routine\n"
        "2. Trace the hashing with strace\n"
        "3. Run it under wine with a candidate key\n\n"
        "Overall the binary looks like a straightforward keygen-me."
    )
    result = _strip_duplicated_next_steps(text)
    assert "Next Technical Threads" not in result
    assert "1. Decompile" not in result
    assert "Trace the hashing" not in result
    # Both the lead-in and the concluding paragraph survive, so nothing but the menu was removed.
    assert "The license check hashes the input" in result
    assert "Overall the binary looks like a straightforward keygen-me." in result


def test_analysis_list_without_next_steps_heading_is_left_alone():
    text = (
        "Here is what the function does:\n"
        "1. Reads 16 bytes from the serial\n"
        "2. XORs them with a rolling key\n"
        "3. Compares against the stored blob"
    )
    # No recognized handoff heading precedes the list, so it may well be analysis -- never strip it.
    assert _strip_duplicated_next_steps(text) == text


def test_russian_heading_block_is_stripped():
    text = (
        "Краткий итог: это keygen-me.\n\n"  # "Краткий итог: это keygen-me."
        "Что дальше:\n"  # "Что дальше:"
        "- X\n"
        "- Y"
    )
    result = _strip_duplicated_next_steps(text)
    assert "Что дальше" not in result
    assert "- X" not in result
    assert "- Y" not in result
    # The summary line that preceded the menu is preserved.
    assert "keygen-me" in result


def test_never_blanks_the_whole_message():
    # The entire reply IS the next-steps block -- stripping it would leave nothing, so it is kept.
    text = "Next steps:\n1. A\n2. B"
    assert _strip_duplicated_next_steps(text) == text


def test_heading_not_followed_by_a_list_is_untouched():
    # A heading-like line with prose (not an enumerated run) under it is not a handoff block.
    text = "Next steps are tricky here because the binary is packed, so let's unpack it first."
    assert _strip_duplicated_next_steps(text) == text


def test_empty_text_returns_as_is():
    assert _strip_duplicated_next_steps("") == ""
