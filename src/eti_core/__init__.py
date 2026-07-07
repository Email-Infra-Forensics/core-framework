"""
eti_core — Email Trust Index Core Framework
Caracterización forense de infraestructura de correo.
"""

__version__ = "0.1.0"
__author__ = "Luis Valdenegro"

from eti_core.models import EmailHeaders, Hop, TrustScore

__all__ = ["EmailHeaders", "Hop", "TrustScore", "__version__"]
