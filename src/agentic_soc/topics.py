"""Topic names on the Kafka-compatible event broker (RFC Figure 1)."""

SIGNIN = "signin"
FLOW = "flow"
PROCESS = "process"
DEAD_LETTER = "dead-letter"
ACTIONS = "actions"

STREAM_TOPICS: dict[str, str] = {"signin": SIGNIN, "flow": FLOW, "process": PROCESS}
ALL_TOPICS: tuple[str, ...] = (SIGNIN, FLOW, PROCESS, DEAD_LETTER, ACTIONS)
