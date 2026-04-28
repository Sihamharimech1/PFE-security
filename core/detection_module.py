# core/detection_module.py

class DetectionModule:
    def __init__(self):
        self.history = {}

    def analyze(self, request):
        agent = request["agent_id"]
        action = request["action"]

        key = (agent, action)
        self.history[key] = self.history.get(key, 0) + 1

        if self.history[key] > 5:
            print(f"[ALERT] Too many '{action}' from {agent}")
            return "ANOMALY"

        return "NORMAL"