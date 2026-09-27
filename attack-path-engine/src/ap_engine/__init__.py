"""Attack-path analysis engine.

Ingests BloodHound/SharpHound JSON, builds a directed graph of Active
Directory relationships, finds escalation paths to high-value targets, scores
them deterministically, and (optionally) has an LLM rank and explain them in
plain English.
"""

__version__ = "0.1.0"
