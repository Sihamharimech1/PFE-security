# show_agent_states.py
# Run this anytime to see current state of all agents in MongoDB.
# Works independently of test_main.py

from storage.agent_repository import AgentRepository

repo = AgentRepository()

print("\n" + "=" * 60)
print("  AGENT STATES — from MongoDB")
print("=" * 60)

states = repo.get_all_states()

if not states:
    print("  No agents registered yet. Run test_main.py first.")
else:
    for s in states:
        status = s.get("status", "unknown")
        icon   = "🟢" if status == "active" else ("🔴" if status == "stopped" else "🟡")
        print(f"\n  {icon}  {s['agent_id']} ({s['role']})")
        print(f"      Status     : {status}")
        print(f"      Created    : {s.get('created_at','?')}")
        print(f"      Updated    : {s.get('updated_at','?')}")
        history = s.get("history", [])
        if len(history) > 1:
            print(f"      History    :")
            for h in history:
                reason = f"  ← {h['reason']}" if h.get("reason") else ""
                print(f"        [{h['changed_at']}]  {h['status']}{reason}")

print("\n" + "=" * 60)