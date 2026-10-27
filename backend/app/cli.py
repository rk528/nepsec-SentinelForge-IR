"""Operator commands.

    python -m app.cli create-org --name "Acme SOC" --slug acme
    python -m app.cli create-user --org acme --email lead@acme.test --name "Lead" --role admin
    python -m app.cli seed-demo
    python -m app.cli reset-demo           # asks you to type the confirmation phrase
    python -m app.cli sync                 # refresh rule and playbook metadata
    python -m app.cli self-test            # evaluate rules against labelled fixtures

Passwords are read interactively (or from SF_NEW_USER_PASSWORD for automation)
and are never accepted as command-line arguments, which leak into shell history.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import func, select

from app.db import get_sessionmaker
from app.detection.engine import run_self_test, sync_rule_metadata
from app.models import Organization, User
from app.playbooks.registry import sync_playbooks
from app.security import hash_password, validate_password_strength
from app.services import demo


def _read_password() -> str:
    pw = os.environ.get("SF_NEW_USER_PASSWORD")
    if not pw:
        pw = getpass.getpass("Password: ")
        if pw != getpass.getpass("Repeat password: "):
            sys.exit("Passwords do not match")
    validate_password_strength(pw)
    return pw


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("create-org")
    o.add_argument("--name", required=True)
    o.add_argument("--slug", required=True)
    u = sub.add_parser("create-user")
    u.add_argument("--org", required=True, help="organisation slug")
    u.add_argument("--email", required=True)
    u.add_argument("--name", required=True)
    u.add_argument("--role", choices=["viewer", "analyst", "lead", "admin"], required=True)
    sub.add_parser("seed-demo")
    r = sub.add_parser("reset-demo")
    r.add_argument("--confirm", help=f'non-interactive confirmation; must equal "{demo.RESET_CONFIRMATION}"')
    sub.add_parser("sync")
    sub.add_parser("self-test")
    args = parser.parse_args(argv)

    with get_sessionmaker()() as db:
        if args.cmd == "create-org":
            if args.slug == demo.DEMO_SLUG:
                sys.exit("The 'demo' slug is reserved for the synthetic demo workspace")
            db.add(Organization(name=args.name, slug=args.slug))
            db.commit()
            print(f"Created organisation {args.slug}")
        elif args.cmd == "create-user":
            org = db.execute(select(Organization).where(Organization.slug == args.org)).scalar_one_or_none()
            if org is None:
                sys.exit("Organisation not found")
            if org.is_demo:
                sys.exit("Password users cannot be added to the demo workspace")
            if db.execute(select(User.id).where(func.lower(User.email) == args.email.lower())).first():
                sys.exit("A user with that email already exists")
            try:
                pw = _read_password()
            except ValueError as exc:
                sys.exit(str(exc))
            db.add(User(org_id=org.id, email=args.email.lower(), display_name=args.name, role=args.role, password_hash=hash_password(pw)))
            db.commit()
            print(f"Created {args.role} {args.email.lower()} in {args.org}")
        elif args.cmd == "seed-demo":
            result = demo.seed_demo(db)
            db.commit()
            print(f"Seeded synthetic demo workspace: {result['alerts']} alerts")
        elif args.cmd == "reset-demo":
            phrase = args.confirm
            if phrase is None:
                print("This permanently deletes the synthetic demo workspace and all of its records.")
                phrase = input(f'Type "{demo.RESET_CONFIRMATION}" to continue: ')
            try:
                deleted = demo.reset_demo(db, phrase)
            except ValueError as exc:
                sys.exit(str(exc))
            db.commit()
            print("Demo workspace deleted" if deleted else "No demo workspace found")
        elif args.cmd == "sync":
            sync_rule_metadata(db)
            sync_playbooks(db)
            db.commit()
            print("Rule and playbook metadata synchronised")
        elif args.cmd == "self-test":
            results = run_self_test(db, None)
            db.commit()
            failed = [r["rule_id"] for r in results if not r["passed"]]
            for r in results:
                print(
                    f"{r['rule_id']}: TP={r['true_positives']} FP={r['false_positives']} TN={r['true_negatives']} FN={r['false_negatives']} precision={r['precision']} recall={r['recall']} {'PASS' if r['passed'] else 'FAIL'}"
                )
            if failed:
                sys.exit(1)


if __name__ == "__main__":
    main()
