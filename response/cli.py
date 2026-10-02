"""Command-line foundation. CLI actor values are asserted identities, never authenticated ones."""
import argparse
import json

from app.config import settings
from database.database import Database
from response.service import ResponseConflict, ResponseForbidden, ResponseNotFound, ResponseService


def _parser():
    parser=argparse.ArgumentParser(prog="python -m response")
    sub=parser.add_subparsers(dest="command",required=True)
    recommend=sub.add_parser("recommend");recommend.add_argument("--incident",required=True);recommend.add_argument("--actor");recommend.add_argument("--dry-run",action="store_true")
    show=sub.add_parser("show");show.add_argument("action_id")
    for name in ("approve","reject","execute","rollback"):
        cmd=sub.add_parser(name);cmd.add_argument("action_id");cmd.add_argument("--expected-status",required=True);cmd.add_argument("--actor",required=True)
        if name=="reject":cmd.add_argument("--reason",default="")
    return parser


def main(argv=None):
    args=_parser().parse_args(argv)
    if args.command!="show" and not args.actor and args.command!="recommend":
        _parser().error("--actor is required for mutation commands")
    if args.command=="recommend" and not args.dry_run and not args.actor:
        _parser().error("--actor is required for mutation commands")
    db=Database(settings.database_path)
    if args.command=="recommend" and args.dry_run:
        if db.current_version()!=9:
            raise SystemExit("dry-run requires an already initialized schema version 9 database; no writes were made")
    else:
        db.initialize()
    service=ResponseService(db)
    try:
        if args.command=="recommend":
            result=service.recommend(args.incident,actor=args.actor or "cli:dry-run",via="cli",dry_run=args.dry_run)
        elif args.command=="show": result=service.get(args.action_id)
        elif args.command=="approve": result=service.approve(args.action_id,expected_status=args.expected_status,actor=args.actor,via="cli")
        elif args.command=="reject": result=service.reject(args.action_id,expected_status=args.expected_status,actor=args.actor,reason=args.reason,via="cli")
        elif args.command=="execute": result=service.execute(args.action_id,expected_status=args.expected_status,actor=args.actor,via="cli")
        else: result=service.rollback(args.action_id,expected_status=args.expected_status,actor=args.actor,via="cli")
    except (ResponseConflict,ResponseForbidden,ResponseNotFound,ValueError) as exc:
        print(json.dumps({"error":str(exc)}));return 2
    print(json.dumps(result,default=str,sort_keys=True,indent=2));return 0
