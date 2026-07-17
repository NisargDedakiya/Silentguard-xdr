"""Entry point: elevate if needed, then launch the GUI.

    python -m silentguard_home
"""
import sys

from .privileges import is_elevated, relaunch_as_admin


def main() -> None:
    # Blocking needs admin; if we're not elevated, relaunch through UAC and exit.
    if not is_elevated() and relaunch_as_admin():
        sys.exit(0)
    from .app import run
    run()


if __name__ == "__main__":
    main()
