"""Deterministic, separately scored variants of the published QA datasets."""

import random
import re


OPTION_HEADER = "\nChoose the correct answer from the following options:\n"
OPTION_LINE = re.compile(r"^\(([A-J])\) (.+)$")
EXPLICIT_ANSWER = re.compile(
    r"(?im)^\s*(?:\*\*)?(?:answer\s*:|(?:the\s+)?answer\s+is)"
    r"(?:\*\*)?\s*\(?([A-J])\)?(?:\*\*)?(?=\s|[.,;]|$)"
)


def shuffle_options(query, gold, seed, index):
    question, header, options = query.partition(OPTION_HEADER)
    rows = [OPTION_LINE.fullmatch(line) for line in options.splitlines() if line.strip()]
    if not header or not rows or not all(rows):
        raise ValueError(f"Unrecognized option layout for task index {index}")
    choices = [row.groups() for row in rows]
    labels = [label for label, _ in choices]
    if gold not in labels or len(labels) != len(set(labels)):
        raise ValueError(f"Invalid option labels for task index {index}")
    random.Random(f"{seed}:{index}").shuffle(choices)
    lines = []
    new_gold = None
    for label, (old_label, option) in zip(labels, choices):
        lines.append(f"({label}) {option}")
        if old_label == gold:
            new_gold = label
    return question + header + "\n".join(lines), new_gold


def explicit_answer(response, query):
    """Read an explicit answer or a standalone final letter among the options."""
    _, _, options = query.partition(OPTION_HEADER)
    labels = {match[1] for line in options.splitlines() if (match := OPTION_LINE.fullmatch(line))}
    matches = {match.upper() for match in EXPLICIT_ANSWER.findall(response)}
    if not matches and response.strip():
        last = response.strip().splitlines()[-1].strip()
        if re.fullmatch(r"[A-J]", last):
            matches = {last}
    if len(matches) == 1 and matches <= labels:
        return matches.pop()
    return None
