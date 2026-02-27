"""Simple payload mutation engine.

The engine applies one or more transformation strategies to a given payload
string.  It is intentionally deterministic and lightweight; payloads are
not sent to the network here.  Higher level code can generate candidates and
re-test them.
"""

from typing import List
import urllib.parse


class MutationEngine:
    """Generate mutated versions of a payload based on requested strategies."""

    def mutate(self, payload: str, strategies: List[str]) -> List[str]:
        """Return a list of mutated payloads.

        Parameters
        ----------
        payload : str
            Original payload string.
        strategies : List[str]
            A list that may include:
            - "url_encode"
            - "double_encode"
            - "case_mutation"
            - "whitespace_injection"
            - "unicode_encode"

        Returns
        -------
        List[str]
            One mutated payload per strategy (order preserved).
        """
        mutated = []
        for strat in strategies:
            if strat == "url_encode":
                mutated.append(urllib.parse.quote(payload))
            elif strat == "double_encode":
                mutated.append(urllib.parse.quote(urllib.parse.quote(payload)))
            elif strat == "case_mutation":
                # alternate upper/lower on letters
                transformed = ''.join(
                    c.upper() if i % 2 == 0 else c.lower()
                    for i, c in enumerate(payload)
                )
                mutated.append(transformed)
            elif strat == "whitespace_injection":
                # insert a space before every special char
                out = ''
                for ch in payload:
                    if ch in ['<', '>', '/', '\\', '"', "'"]:
                        out += ' ' + ch
                    else:
                        out += ch
                mutated.append(out)
            elif strat == "unicode_encode":
                # simple percent-encoding style
                out = ''.join(f"%u{ord(c):04x}" for c in payload)
                mutated.append(out)
            else:
                # unknown strategy - leave original
                mutated.append(payload)
        return mutated
