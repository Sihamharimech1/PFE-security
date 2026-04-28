# core/detection_module.py

FREQUENCY_THRESHOLD = 5  # alert triggers on the 5th call and beyond

class DetectionModule:
    def __init__(self):
        self.history = {}

    def analyze(self, request):
        agent  = request["agent_id"]
        action = request["action"]

        key = (agent, action)
        self.history[key] = self.history.get(key, 0) + 1
        count = self.history[key]

        print(f"[DETECTION] {agent} | '{action}' | call #{count}")

        if count >= FREQUENCY_THRESHOLD:
            print(f"[ANOMALY DETECTED] '{action}' called {count} times by {agent} — threshold is {FREQUENCY_THRESHOLD}")
            return "ANOMALY"

        return "NORMAL"