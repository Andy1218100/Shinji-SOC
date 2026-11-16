"""Prepara el import de los modulos del agente para los tests.

Los tests corren con el Python de cualquier equipo (no hace falta el venv
del agente): si faltan httpx o psutil se reemplazan por modulos vacios,
porque las funciones que se prueban no los usan.
"""

import os
import sys
import types

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

for name in ("httpx", "psutil"):
    try:
        __import__(name)
    except ImportError:
        stub = types.ModuleType(name)
        stub.AsyncClient = object  # solo para anotaciones de tipo
        sys.modules[name] = stub
