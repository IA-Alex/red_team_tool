#!/usr/bin/env python
import sys
from typing import Any, Dict

from redteamcrew.crew import RedteamcrewCrew

# This main file is intended to be a way for your to run your
# crew locally, so refrain from adding unnecessary logic into this file.
# Replace with inputs you want to test with, it will automatically
# interpolate any tasks and agents information


def default_inputs() -> Dict[str, Any]:
    return {
        "authorized_scope": "sample_value",
        "engagement_name": "sample_value",
        "company_name": "sample_value",
        "rules_of_engagement": "sample_value",
    }


def run() -> None:
    """
    Run the crew.
    """
    RedteamcrewCrew().crew().kickoff(inputs=default_inputs())


def train() -> None:
    """
    Train the crew for a given number of iterations.
    """
    try:
        RedteamcrewCrew().crew().train(
            n_iterations=int(sys.argv[1]), filename=sys.argv[2], inputs=default_inputs()
        )

    except Exception as e:
        raise Exception(f"An error occurred while training the crew: {e}")


def replay() -> None:
    """
    Replay the crew execution from a specific task.
    """
    try:
        RedteamcrewCrew().crew().replay(task_id=sys.argv[1])

    except Exception as e:
        raise Exception(f"An error occurred while replaying the crew: {e}")


def test() -> None:
    """
    Test the crew execution and returns the results.
    """
    try:
        RedteamcrewCrew().crew().test(
            n_iterations=int(sys.argv[1]),
            eval_llm=sys.argv[2],
            inputs=default_inputs(),
        )

    except Exception as e:
        raise Exception(f"An error occurred while testing the crew: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:  # noqa: PLR2004 - número mínimo de argumentos requeridos
        print("Usage: main.py <command> [<args>]")
        sys.exit(1)

    command = sys.argv[1]
    if command == "run":
        run()
    elif command == "train":
        train()
    elif command == "replay":
        replay()
    elif command == "test":
        test()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
