from pathlib import Path
import sys
from typing import TypedDict

from agent_tail import AgentTailCallbackHandler
from langgraph.graph import END, START, StateGraph


class State(TypedDict):
    value: int


def increment(state: State) -> State:
    return {"value": state["value"] + 1}


def main() -> None:
    output = Path(sys.argv[1] if len(sys.argv) > 1 else "langgraph-demo.jsonl")
    builder = StateGraph(State)
    builder.add_node("increment", increment)
    builder.add_edge(START, "increment")
    builder.add_edge("increment", END)
    graph = builder.compile()

    with AgentTailCallbackHandler(output) as callback:
        graph.invoke({"value": 1}, {"callbacks": [callback]})

    print(output)


if __name__ == "__main__":
    main()
