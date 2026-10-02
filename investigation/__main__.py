"""CLI for evidence-bounded incident investigation."""
import argparse
import json
import sys

from app.config import settings
from investigation.service import InvestigationError, InvestigationService


def main(argv=None):
    parser=argparse.ArgumentParser(prog="python -m investigation")
    parser.add_argument("incident_id")
    parser.add_argument("--db",default=str(settings.database_path))
    parser.add_argument("--force",action="store_true",help="Create a new run even if a completed run can be reused")
    parser.add_argument("--dry-run",action="store_true",help="Read-only packet preview; never migrates or calls an LLM")
    parser.add_argument("--show-prompt",action="store_true",help="Print the generated prompt without calling an LLM")
    parser.add_argument("--created-by",default="cli",help="Explicit investigation actor ID (defaults to cli)")
    args=parser.parse_args(argv)
    try:
        service=InvestigationService(args.db)
        result=service.investigate(args.incident_id,force=args.force,dry_run=args.dry_run,
            show_prompt=args.show_prompt,created_by=args.created_by)
    except (InvestigationError,LookupError,ValueError,FileNotFoundError) as exc:
        print(str(exc),file=sys.stderr)
        return 2
    if args.show_prompt:
        print(result.pop("prompt") or "")
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    print(json.dumps(result,indent=2,sort_keys=True,ensure_ascii=False))
    if result.get("status") in {"failed","invalid","retry_limit"}: return 1
    return 0


if __name__=="__main__": raise SystemExit(main())
