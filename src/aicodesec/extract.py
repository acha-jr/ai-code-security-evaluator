"""Pull the code block out of a model reply. The code itself is never edited.

Models usually answer with some chat text and a block of code between ``` marks
(a "code fence"). We keep only the code, and we write down what we threw away.
"""
import re
from dataclasses import dataclass

# A regular expression that finds code fences. In plain words it means:
#   a line that starts with ```, an optional language word like "python", a new line,
#   then everything up to the next line that starts with ```.
# MULTILINE lets ^ and $ match at every line. DOTALL lets "." match across lines.
FENCE = re.compile(r"^```[\w+-]*[ \t]*\n(.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)


@dataclass
class Extraction:
    """The extracted code plus a plain note about what was dropped."""

    code: str  # The code exactly as the model wrote it.
    note: str  # A sentence for the metadata, for example "Prose outside the code fence was dropped".
    prose_dropped: bool  # True if there was chat text outside the fence that we did not keep.


def extract_code(reply: str) -> Extraction:
    """Return the code from a reply exactly as written, and say what was left out."""
    # Collect the text inside every fence. There can be several (code, then a run command, and so on).
    blocks = [match.group(1) for match in FENCE.finditer(reply)]
    if not blocks:
        # No fence at all: the model may have sent bare code. Keep everything, and say so.
        return Extraction(reply, "No code fence found. The whole reply was saved as code.", False)

    # Prefer the block that defines create_app, since the prompt asks for it.
    # Otherwise take the longest one, which is most likely the main program.
    with_app = [block for block in blocks if "create_app" in block]
    code = with_app[0] if with_app else max(blocks, key=len)

    # Remove every fenced block from the reply. Whatever text is left was chat prose.
    outside = FENCE.sub("", reply).strip()
    if outside:
        note = f"Prose outside the code fence was dropped ({len(blocks)} code block(s) found)."
    else:
        note = f"Reply was only code ({len(blocks)} code block(s) found)."
    if len(blocks) > 1:
        note += " The block that defines create_app was used." if with_app else " The longest block was used."
    return Extraction(code, note, bool(outside))
