"""`python -m auditor.agents.evaluator` : lance l'Évaluateur A2A (port 10002 par défaut)."""

import uvicorn

from auditor.a2a_common import agent_port
from auditor.agents.evaluator.server import create_app

if __name__ == "__main__":
    uvicorn.run(create_app(), host="127.0.0.1", port=agent_port("evaluator"))
