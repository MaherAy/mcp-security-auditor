"""`python -m auditor.agents.orchestrator` : lance l'orchestrateur A2A (port 10000 par défaut)."""

import uvicorn

from auditor.a2a_common import agent_port
from auditor.agents.orchestrator.server import create_app

if __name__ == "__main__":
    uvicorn.run(create_app(), host="127.0.0.1", port=agent_port("orchestrator"))
