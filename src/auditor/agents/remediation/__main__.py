"""`python -m auditor.agents.remediation` : lance l'agent Remédiation A2A (port 10003 par défaut)."""

import uvicorn

from auditor.a2a_common import agent_port
from auditor.agents.remediation.server import create_app

if __name__ == "__main__":
    uvicorn.run(create_app(), host="127.0.0.1", port=agent_port("remediation"))
