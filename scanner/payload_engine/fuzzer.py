"""Fuzzing and payload mutation engine."""

import random
import string
from typing import List, Dict, Any, Callable


class FuzzingEngine:
    """
    Advanced fuzzing engine for vulnerability discovery.
    
    Generates mutated payloads through random variation and pattern analysis.
    """
    
    # Common fuzzing patterns
    FUZZ_PATTERNS = {
        'integers': ['-1', '0', '1', '999', '10000', '2147483647', '-2147483648'],
        'strings': [
            '',
            'a',
            '123',
            'admin',
            'test',
            'null',
            'undefined',
            'true',
            'false',
        ],
        'special_chars': [
            '!@#$%^&*()',
            '<script>',
            '{{}}',
            '&&',
            '||',
            ';;',
            '--',
        ],
        'format_strings': [
            '%x',
            '%n',
            '%s',
            '%p',
            '%ld',
            '%p%p%p%p',
        ],
        'buffer_overflow': [
            'A' * 100,
            'A' * 1000,
            'A' * 10000,
        ],
    }
    
    def __init__(self, seed: int = None):
        """Initialize fuzzing engine."""
        if seed:
            random.seed(seed)
            
    def generate_fuzz_inputs(
        self,
        base_input: str = '',
        patterns: List[str] = None,
        count: int = 10,
    ) -> List[str]:
        """
        Generate fuzzed inputs from patterns.
        
        Parameters
        ----------
        base_input : str
            Base input to append to.
        patterns : List[str]
            Pattern categories to use.
        count : int
            Number of fuzz inputs to generate.
            
        Returns
        -------
        List[str]
            List of fuzzed inputs.
        """
        if patterns is None:
            patterns = list(self.FUZZ_PATTERNS.keys())
            
        fuzz_inputs = []
        for _ in range(count):
            pattern_type = random.choice(patterns)
            pattern_values = self.FUZZ_PATTERNS.get(pattern_type, [])
            
            if pattern_values:
                fuzz_input = base_input + random.choice(pattern_values)
            else:
                fuzz_input = base_input + self._generate_random_string()
                
            fuzz_inputs.append(fuzz_input)
            
        return fuzz_inputs
        
    def mutate_payload(self, payload: str, mutation_rate: float = 0.3) -> str:
        """
        Mutate payload by random character variation.
        
        Parameters
        ----------
        payload : str
            Original payload.
        mutation_rate : float
            Probability (0-1) of mutating each character.
            
        Returns
        -------
        str
            Mutated payload.
        """
        mutated = []
        for char in payload:
            if random.random() < mutation_rate:
                if char.isalpha():
                    mutated.append(random.choice(string.ascii_letters))
                elif char.isdigit():
                    mutated.append(random.choice(string.digits))
                else:
                    mutated.append(random.choice(string.punctuation))
            else:
                mutated.append(char)
                
        return ''.join(mutated)
        
    def generate_grammar_based_payloads(
        self,
        grammar: Dict[str, List[str]],
        start_symbol: str = '<Payload>',
        count: int = 10,
    ) -> List[str]:
        """
        Generate payloads from context-free grammar.
        
        Parameters
        ----------
        grammar : Dict[str, List[str]]
            Grammar rules.
        start_symbol : str
            Starting symbol.
        count : int
            Number of payloads to generate.
            
        Returns
        -------
        List[str]
            Generated payloads.
        """
        payloads = []
        for _ in range(count):
            payload = self._expand_grammar(start_symbol, grammar, depth=0, max_depth=5)
            payloads.append(payload)
            
        return payloads
        
    def _expand_grammar(
        self,
        symbol: str,
        grammar: Dict[str, List[str]],
        depth: int = 0,
        max_depth: int = 5,
    ) -> str:
        """Recursively expand grammar symbol."""
        if depth > max_depth or symbol not in grammar:
            return symbol
            
        options = grammar[symbol]
        choice = random.choice(options)
        
        # Check if choice contains other symbols
        expanded = choice
        for key in grammar.keys():
            if f'<{key}>' in expanded:
                expanded = expanded.replace(f'<{key}>', 
                    self._expand_grammar(key, grammar, depth + 1, max_depth))
                
        return expanded
        
    def _generate_random_string(
        self,
        length: int = 10,
        chars: str = string.ascii_letters + string.digits
    ) -> str:
        """Generate random string."""
        return ''.join(random.choice(chars) for _ in range(length))
