$ErrorActionPreference = "Stop"

$documentPath = "C:\PFE-security\docs\PFE_report_corrected_consistent.docx"
$wdReplaceAll = 2
$wdFindContinue = 1
$wdCollapseEnd = 0
$wdPageBreak = 7
$wdAutoFitWindow = 2

function Replace-AllText {
    param(
        [Parameter(Mandatory = $true)] $Document,
        [Parameter(Mandatory = $true)] [string] $Old,
        [Parameter(Mandatory = $true)] [string] $New
    )

    if ($Old.Length -gt 240 -or $New.Length -gt 240) {
        foreach ($paragraph in $Document.Paragraphs) {
            $paragraphText = ($paragraph.Range.Text -replace "[`r`a]$", "")
            if ($paragraphText -eq $Old) {
                $replacementRange = $paragraph.Range.Duplicate
                $replacementRange.End = $replacementRange.End - 1
                $replacementRange.Text = $New
            }
        }
        return
    }

    foreach ($story in $Document.StoryRanges) {
        $range = $story
        while ($null -ne $range) {
            $find = $range.Find
            $find.ClearFormatting()
            $find.Replacement.ClearFormatting()
            $find.Text = $Old
            $find.Replacement.Text = $New
            $find.Forward = $true
            $find.Wrap = $wdFindContinue
            $find.Format = $false
            $find.MatchCase = $false
            $find.MatchWholeWord = $false
            [void] $find.Execute(
                $Old,
                $false,
                $false,
                $false,
                $false,
                $false,
                $true,
                $wdFindContinue,
                $false,
                $New,
                $wdReplaceAll
            )
            $range = $range.NextStoryRange
        }
    }
}

function Add-StyledParagraph {
    param(
        [Parameter(Mandatory = $true)] $Selection,
        [Parameter(Mandatory = $true)] [string] $Text,
        [Parameter(Mandatory = $true)] [string] $Style
    )

    $Selection.Style = $Style
    $Selection.TypeText($Text)
    $Selection.TypeParagraph()
}

$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0

try {
    $doc = $word.Documents.Open($documentPath)

    $replacements = [ordered]@{
        "The proposed architecture is evaluated through four representative scenarios: normal system operation, unauthorized action attempts, behavioral anomalies, and interactions with malicious inputs simulating prompt injection attacks." =
            "The proposed architecture is evaluated through five representative scenarios: normal system operation, unauthorized action attempts, behavioral anomalies, interactions with malicious inputs simulating prompt injection attacks, and role identity inconsistency."
        "L’architecture proposée est évaluée à travers quatre scénarios représentatifs : le fonctionnement normal du système, les tentatives d’actions non autorisées, les comportements anormaux des agents et les interactions avec des entrées malveillantes simulant des attaques par injection de prompt." =
            "L’architecture proposée est évaluée à travers cinq scénarios représentatifs : le fonctionnement normal du système, les tentatives d’actions non autorisées, les comportements anormaux des agents, les interactions avec des entrées malveillantes simulant des attaques par injection de prompt et les incohérences entre l’identité d’un agent et le rôle qu’il revendique."
        "The evaluation is conducted through several practical scenarios, including normal system operation, unauthorized action attempts, behavioral anomalies, and malicious input interactions simulating prompt injection attacks." =
            "The evaluation is conducted through five practical scenarios covering normal operation, unauthorized actions, behavioral drift, malicious input, and inconsistency between an agent's registered identity and its claimed role."
        "Chapter 5 describes the testing and evaluation process through different security scenarios and discusses the results obtained." =
            "Chapter 5 describes the testing and evaluation process through five security scenarios and discusses the observed results."
        "The Human Administrator is responsible for supervising and managing the entire system where he can perform the following operations:" =
            "The Human Administrator supervises the operational state of the prototype through a restricted dashboard. The interface intentionally exposes operational information without exposing private authorization policies."
        "Create and configure intelligent agents." =
            "Review registered intelligent agents and their operational state."
        "Assign roles and permissions." =
            "Activate, suspend, or stop registered agents."
        "Launch evaluation scenarios." =
            "Review the predefined evaluation scenarios and their outcomes."
        "Create and manage intelligent agents" =
            "Register and manage intelligent-agent state"
        "Assign roles and permissions to agents" =
            "Enforce centrally managed roles and permissions"
        "Execute predefined evaluation scenarios" =
            "Display predefined evaluation scenarios and results"
        "The system must allow the administrator to create, activate, suspend, and remove intelligent agents." =
            "The prototype registers agents from the backend and allows an authorized operator to activate, suspend, or stop their persisted operational state from the dashboard. Agent creation, deletion, and role assignment remain backend-controlled operations."
        "To validate the effectiveness of the proposed architecture, four representative scenarios were defined." =
            "To validate the effectiveness of the proposed architecture, five representative scenarios were defined."
        "The RBAC permission table is stored in MongoDB and can be dynamically modified by the administrator via the dashboard, without system restart. This flexibility is essential for testing different security configurations during scenarios." =
            "The RBAC policy is stored as a private, versioned document in MongoDB. It is intentionally neither displayed nor editable through the supervision dashboard. A validated JSON policy is used only to bootstrap an empty collection or as an emergency fallback when MongoDB is unavailable. This separation limits the exposure of sensitive authorization information and reduces the risk of unauthorized policy changes."
        "The Detection Module analyzes agent behavior in real time for abnormal patterns. It implements a set of configurable rules:" =
            "The Detection Module analyzes agent behavior in near real time using deterministic rules whose thresholds are configured in the backend:"
        "The Incident Management Module orchestrates automated responses to detected anomalies according to a three-level severity scale:" =
            "The Incident Management Module orchestrates graduated responses through five persistent limitation states: NORMAL, WATCH, DEGRADED, RESTRICTED, and SUSPENDED."
        "Alert level (low severity): records the incident in the journal and notifies the administrator via the dashboard, without disrupting agent operation." =
            "WATCH level: records the incident, exposes it in the dashboard, and increases monitoring without blocking normal operation."
        "Limitation level (medium severity): imposes a forced delay between actions of the offending agent, reducing its operation rate." =
            "DEGRADED level: imposes a delay between requests. Repeated anomalies escalate the agent to RESTRICTED, where only low-sensitivity actions remain available."
        "Suspension level (high severity): completely suspends the agent, which can no longer execute actions until manual administrator intervention." =
            "SUSPENDED level: blocks all further requests until an authorized operator reactivates the agent. WATCH, DEGRADED, and RESTRICTED states recover progressively after a quiet period."
        "scenarios/" =
            "scenarios/"
        "Demonstration scripts: scenario_1.py through scenario_4.py" =
            "Demonstration scripts: scenario_1_normal.py through scenario_5_role_inconsistency.py"
        "YAML configuration files: rbac_policies.yaml, detection_rules.yaml" =
            "Validated JSON bootstrap and emergency fallback policy: policies.json"
        "Interface: app.py, pages/" =
            "React interface and Python dashboard API: api_server.py, web/src/pages/"
        "The Administrator can create agents, assign roles, supervise the system in real time, configure detection rules, and manage triggered incidents." =
            "The implemented dashboard allows an authorized operator to supervise registered agents, change their operational status, inspect logs and activity, search incidents, and manage incident lifecycle status. Agent creation, role assignment, RBAC editing, and detection-rule editing are deliberately kept outside the dashboard."
        "The Detection Module receives validated actions from the Control Module and analyzes them according to rules stored in the database." =
            "The Detection Module receives validated actions from the Control Module and analyzes them using backend-configured sliding-window rules."
        "The Supervision Module directly reads MongoDB logs to feed the dashboard." =
            "The Supervision API reads MongoDB repositories and exposes a restricted JSON interface consumed by the React dashboard."
        "The system defines five operational roles, each corresponding to one intelligent agent implemented in the prototype." =
            "The system defines five operational roles aligned with the responsibilities of the five intelligent agents implemented in the prototype."
        "Collector`rread_data,`rfetch_api,`rlist_resources" =
            "Collector`rread_data, fetch_api"
        "> 10 identical actions in 60-second window" =
            ">= 5 identical actions in a 60-second sliding window by default"
        "Threshold is configurable by the administrator." =
            "The threshold is configurable in the backend detector constructor."
        "3 consecutive out-of-role attempts in 120 seconds" =
            "3 role-identity mismatches in a 120-second sliding window"
        "Signals possible agent compromise or internal logic drift. Triggers enhanced monitoring and administrator notification." =
            "Detects a mismatch between the role claimed in a request and the authoritative role stored for the agent. The first event triggers an alert; repeated events trigger suspension."
        "Role inconsistency rule (repeated) or malicious pattern detected." =
            "Repeated RBAC violations or repeated role-identity inconsistencies. Malicious external input is blocked and recorded as an alert because it does not by itself prove that the receiving agent is compromised."
        "Unix timestamp with millisecond precision" =
            "UTC datetime generated by the backend"
        "Action parameters (after anonymization of sensitive data)" =
            "Action parameters as supplied to the prototype; production deployment would require redaction of secrets and personal data"
        "MongoDB indexes are defined on the fields agent_id, timestamp, and action_type to ensure acceptable query performance even on large log volumes." =
            "MongoDB indexes are defined on timestamp, agent.id, request.action, severity, risk level, detection status, incident identifier, and blocked status to support operational queries."
    }

    foreach ($entry in $replacements.GetEnumerator()) {
        Replace-AllText -Document $doc -Old $entry.Key -New $entry.Value
    }

    # Correct the RBAC table cells while preserving the existing table style.
    foreach ($table in $doc.Tables) {
        $text = $table.Range.Text
        if ($text -like "*Assigned Agents*" -and $text -like "*Collector*") {
            $rows = $table.Rows.Count
            for ($row = 2; $row -le $rows; $row++) {
                $role = ($table.Cell($row, 1).Range.Text -replace "[`r`a]", "").Trim()
                switch ($role) {
                    "Collector" {
                        $table.Cell($row, 2).Range.Text = "read_data, fetch_api"
                        $table.Cell($row, 3).Range.Text = "write_data, delete_data, modify_config, suspend_agent"
                        $table.Cell($row, 4).Range.Text = "Agent 1 (Collector)"
                    }
                    "Analyst" {
                        $table.Cell($row, 2).Range.Text = "read_data, direct_answer, analyze_data"
                        $table.Cell($row, 3).Range.Text = "write_report, delete_data, modify_config, suspend_agent"
                        $table.Cell($row, 4).Range.Text = "Agent 2 (Analyst)"
                    }
                    "Writer" {
                        $table.Cell($row, 2).Range.Text = "read_data, write_report, format_document, save_report"
                        $table.Cell($row, 3).Range.Text = "fetch_api, delete_data, modify_config, kill_switch"
                        $table.Cell($row, 4).Range.Text = "Agent 3 (Writer)"
                    }
                    "Executor" {
                        $table.Cell($row, 2).Range.Text = "execute_action, delete_data, write_data, run_command"
                        $table.Cell($row, 3).Range.Text = "modify_config, suspend_agent, kill_switch"
                        $table.Cell($row, 4).Range.Text = "Agent 4 (Executor)"
                    }
                    "Administrator" {
                        $table.Cell($row, 2).Range.Text = "Inherited permissions plus suspend_agent, resume_agent, kill_switch, modify_config, view_logs"
                        $table.Cell($row, 3).Range.Text = "None within the prototype policy"
                        $table.Cell($row, 4).Range.Text = "Agent 5 (Administrator)"
                    }
                }
            }
            break
        }
    }

    # Add the fifth scenario to the existing requirements table.
    foreach ($table in $doc.Tables) {
        $text = $table.Range.Text
        if ($text -like "*Normal Operation*" -and $text -like "*Malicious Input*") {
            $newRow = $table.Rows.Add()
            $newRow.Cells.Item(1).Range.Text = "S5"
            $newRow.Cells.Item(2).Range.Text = "Role Identity Inconsistency"
            $newRow.Cells.Item(3).Range.Text = "A registered agent claims a role different from its authoritative MongoDB role. The request is blocked before RBAC evaluation and repeated mismatches cause suspension."
            $newRow.Cells.Item(4).Range.Text = "Validates authoritative identity enforcement and resistance to privilege escalation."
            break
        }
    }

    # Update the incident response table to reflect the implemented graduated model.
    foreach ($table in $doc.Tables) {
        $text = $table.Range.Text
        if ($text -like "*Automated Action*" -and $text -like "*KILL SWITCH*") {
            $table.Cell(2, 1).Range.Text = "WATCH / ALERT"
            $table.Cell(2, 2).Range.Text = "Low"
            $table.Cell(2, 3).Range.Text = "Records an incident and increases monitoring without blocking ordinary requests."
            $table.Cell(2, 4).Range.Text = "First role inconsistency or malicious external input."

            $limitRow = $table.Rows.Add($table.Rows.Item(3))
            $limitRow.Cells.Item(1).Range.Text = "DEGRADED / RESTRICTED"
            $limitRow.Cells.Item(2).Range.Text = "Medium"
            $limitRow.Cells.Item(3).Range.Text = "Throttles requests, then restricts non-low-sensitivity actions after repeated anomalies."
            $limitRow.Cells.Item(4).Range.Text = "Excessive-frequency anomaly or repeated limitation event."

            # Locate rows by their first-cell labels after insertion.
            for ($row = 2; $row -le $table.Rows.Count; $row++) {
                $label = ($table.Cell($row, 1).Range.Text -replace "[`r`a]", "").Trim()
                if ($label -eq "SUSPENSION") {
                    $table.Cell($row, 3).Range.Text = "Sets the persistent limitation state to SUSPENDED and blocks all requests until authorized reactivation."
                    $table.Cell($row, 4).Range.Text = "Repeated RBAC violations or repeated role-identity inconsistencies."
                }
            }
            break
        }
    }

    # Insert the missing evaluation and conclusion chapters before references.
    $referenceRange = $null
    for ($paragraphIndex = $doc.Paragraphs.Count; $paragraphIndex -ge 1; $paragraphIndex--) {
        $candidate = $doc.Paragraphs.Item($paragraphIndex).Range
        $candidateText = ($candidate.Text -replace "[`r`a]", "").Trim()
        if ($candidateText -eq "Bibliographic References") {
            $referenceRange = $candidate.Duplicate
            break
        }
    }
    if ($null -eq $referenceRange) {
        throw "Bibliographic References heading was not found."
    }

    $selection = $word.Selection
    $selection.SetRange($referenceRange.Start, $referenceRange.Start)
    $selection.InsertBreak($wdPageBreak)

    Add-StyledParagraph $selection "Chapter 5: Testing, Results and Evaluation" "heading 1"
    Add-StyledParagraph $selection "5.1 Introduction" "heading 2"
    Add-StyledParagraph $selection "This chapter evaluates the implemented prototype against the functional and security requirements defined in Chapter 2. The evaluation combines automated unit and integration tests with five representative security scenarios. The objective is to verify that legitimate operations remain available while malformed, unauthorized, anomalous, or identity-inconsistent requests are blocked or contained before they can cause unsafe execution." "Normal"

    Add-StyledParagraph $selection "5.2 Evaluation Environment and Method" "heading 2"
    Add-StyledParagraph $selection "The prototype was evaluated in a local environment using Python for the agent and security backend, MongoDB for persistence, and a React dashboard for supervision. Each request traverses the same security pipeline: schema validation, authoritative identity verification, limitation enforcement, RBAC authorization, malicious-input filtering, behavioral detection, controlled execution, incident response, and audit logging. Tests use dependency injection and deterministic clocks where necessary so that security decisions can be reproduced." "Normal"
    Add-StyledParagraph $selection "The automated suite contains 37 tests covering policy loading, MongoDB policy fallback, request validation, role authorization, role inconsistency, malicious-input filtering, sliding-window anomaly detection, graduated limitation states, automatic recovery, incident persistence, repository query construction, execution safety, typed models, and the five official scenarios. At the time of validation, all 37 tests passed." "Normal"

    Add-StyledParagraph $selection "5.3 Scenario Evaluation" "heading 2"
    Add-StyledParagraph $selection "5.3.1 Scenario 1 - Normal Operation" "heading 3"
    Add-StyledParagraph $selection "Five agents perform actions compatible with their authoritative roles. The control layer validates each request, RBAC returns ALLOWED, no anomaly is raised, the execution layer completes the permitted action, and an audit document is stored. The observed result confirms that the security controls preserve expected functionality under nominal conditions." "Normal"
    Add-StyledParagraph $selection "5.3.2 Scenario 2 - Forbidden Action" "heading 3"
    Add-StyledParagraph $selection "A collector attempts a high-impact action that is not authorized for the collector role. The request is rejected at the RBAC stage before execution. The denial, attempted action, risk metadata, and final blocked status are recorded. Repeated RBAC violations are tracked in a sliding window and can suspend the registered agent." "Normal"
    Add-StyledParagraph $selection "5.3.3 Scenario 3 - Behavioral Drift" "heading 3"
    Add-StyledParagraph $selection "An agent repeats the same action until the configured frequency threshold is reached. The detector emits an EXCESSIVE_FREQUENCY event and the incident module applies a LIMIT response. The persistent limitation state changes from NORMAL to DEGRADED, causing subsequent requests to be throttled. Repeated anomalies escalate the state to RESTRICTED, where only low-sensitivity actions remain available. After a configured quiet period, the state recovers progressively." "Normal"
    Add-StyledParagraph $selection "5.3.4 Scenario 4 - Malicious Input" "heading 3"
    Add-StyledParagraph $selection "A request contains a suspicious instruction pattern associated with prompt injection. Parameter filtering blocks the request before execution and produces a MALICIOUS_INPUT_PATTERN event. The system records an alert and places the known agent under enhanced monitoring. It does not automatically suspend the receiving agent after a single hostile external input because the input alone is not evidence that the agent itself is compromised." "Normal"
    Add-StyledParagraph $selection "5.3.5 Scenario 5 - Role Identity Inconsistency" "heading 3"
    Add-StyledParagraph $selection "A registered agent submits a request while claiming a role different from the authoritative role stored in MongoDB. The control module blocks the request before RBAC evaluation, preventing the claimed role from influencing authorization. The first mismatch generates an alert; repeated mismatches within the configured sliding window suspend the agent. This scenario demonstrates resistance to a direct privilege-escalation attempt based on forged role metadata." "Normal"

    Add-StyledParagraph $selection "5.4 Dashboard and Traceability Validation" "heading 2"
    Add-StyledParagraph $selection "The Supervision Center retrieves operational data through the dashboard API and refreshes it every five seconds. It therefore provides near-real-time rather than event-stream-based monitoring. The interface presents agent status and limitation level, recent audit events, alerts, searchable incidents, incident lifecycle controls, global activity, and per-agent activity and risk graphs. Agent detail views include status and limitation history. RBAC policy contents are intentionally absent from the dashboard to preserve the separation between operational supervision and sensitive authorization administration." "Normal"

    Add-StyledParagraph $selection "5.5 Requirement Coverage" "heading 2"
    $coverageTable = $doc.Tables.Add($selection.Range, 7, 3)
    $coverageTable.Style = $doc.Tables.Item(1).Style
    $coverageTable.Cell(1, 1).Range.Text = "Requirement area"
    $coverageTable.Cell(1, 2).Range.Text = "Status"
    $coverageTable.Cell(1, 3).Range.Text = "Evidence"
    $coverageTable.Cell(2, 1).Range.Text = "Pre-execution control"
    $coverageTable.Cell(2, 2).Range.Text = "Implemented"
    $coverageTable.Cell(2, 3).Range.Text = "Validation, identity, limitation, RBAC, filtering, and controlled execution pipeline."
    $coverageTable.Cell(3, 1).Range.Text = "Monitoring and audit"
    $coverageTable.Cell(3, 2).Range.Text = "Implemented"
    $coverageTable.Cell(3, 3).Range.Text = "MongoDB audit records, indexed queries, dashboard logs, alerts, incidents, and activity views."
    $coverageTable.Cell(4, 1).Range.Text = "Behavioral detection"
    $coverageTable.Cell(4, 2).Range.Text = "Implemented"
    $coverageTable.Cell(4, 3).Range.Text = "Sliding-window frequency, repeated RBAC violation, role inconsistency, unknown identity, and malicious-input rules."
    $coverageTable.Cell(5, 1).Range.Text = "Incident response"
    $coverageTable.Cell(5, 2).Range.Text = "Implemented"
    $coverageTable.Cell(5, 3).Range.Text = "WATCH, DEGRADED, RESTRICTED, SUSPENDED, recovery, incident lifecycle, and backend kill switch."
    $coverageTable.Cell(6, 1).Range.Text = "Dashboard administration"
    $coverageTable.Cell(6, 2).Range.Text = "Partial by design"
    $coverageTable.Cell(6, 3).Range.Text = "Operational status and incident lifecycle are manageable; RBAC, roles, and detection rules remain private backend controls."
    $coverageTable.Cell(7, 1).Range.Text = "Scenario execution"
    $coverageTable.Cell(7, 2).Range.Text = "Backend/test suite"
    $coverageTable.Cell(7, 3).Range.Text = "Five executable Python scenarios and automated tests; the dashboard displays scenario definitions rather than launching code."
    $coverageTable.AutoFitBehavior($wdAutoFitWindow)
    $selection.SetRange($coverageTable.Range.End, $coverageTable.Range.End)
    $selection.TypeParagraph()

    Add-StyledParagraph $selection "5.6 Discussion" "heading 2"
    Add-StyledParagraph $selection "The evaluation confirms that the architecture enforces a mandatory security checkpoint and records the resulting decisions. A key strength is the use of the MongoDB agent state as the authoritative source for role identity, which prevents a request from granting itself additional permissions by changing its claimed role. Another strength is proportional incident response: suspicious activity does not always cause immediate suspension, while repeated or higher-confidence violations lead to stronger containment." "Normal"
    Add-StyledParagraph $selection "The evaluation also identifies boundaries. Detection remains deterministic and rule-based rather than machine-learning-based. The prototype uses periodic dashboard polling and local deployment. Detection thresholds are backend configuration values, and the dashboard does not create agents, assign roles, edit RBAC, or modify detection rules. These restrictions reduce the administrative attack surface and should be presented as deliberate prototype boundaries rather than implemented features." "Normal"

    $selection.InsertBreak($wdPageBreak)
    Add-StyledParagraph $selection "Chapter 6: General Conclusion and Perspectives" "heading 1"
    Add-StyledParagraph $selection "6.1 General Conclusion" "heading 2"
    Add-StyledParagraph $selection "This thesis presented the design, implementation, and evaluation of a secure architecture for supervising intelligent agents in a multi-agent environment. The proposed solution integrates five specialized agents with a mandatory control pipeline combining request validation, authoritative role verification, private MongoDB-backed RBAC, malicious-input filtering, behavioral anomaly detection, risk scoring, graduated incident response, controlled execution, and centralized audit logging." "Normal"
    Add-StyledParagraph $selection "The prototype demonstrates that agent autonomy can be constrained without preventing legitimate operation. Authorized actions pass through the control layer and execute normally, while unauthorized actions, malformed requests, malicious inputs, excessive repetition, unknown identities, and forged role claims are blocked or contained. Persistent limitation states provide a proportional alternative to immediate suspension, and the supervision dashboard gives operators near-real-time visibility into logs, alerts, incidents, risk, activity, and agent state without exposing sensitive RBAC policy contents." "Normal"
    Add-StyledParagraph $selection "The five evaluation scenarios and the 37 passing automated tests support the functional validity of the prototype. The work therefore meets its central objective: demonstrating a practical Security-by-Design approach in which governance, authorization, monitoring, incident response, and traceability are integrated directly into the agent execution lifecycle." "Normal"

    Add-StyledParagraph $selection "6.2 Main Contributions" "heading 2"
    Add-StyledParagraph $selection "The principal contributions are a modular security checkpoint that agents cannot bypass; private and versioned authorization policy persistence; authoritative role-identity verification; deterministic detection with explainable risk metadata; persistent and recoverable limitation levels; incident lifecycle management; an execution layer with network, filesystem, and command safety controls; and a supervision dashboard that correlates agent state, incidents, audit records, and activity." "Normal"

    Add-StyledParagraph $selection "6.3 Limitations" "heading 2"
    Add-StyledParagraph $selection "The system remains an academic prototype deployed locally. Detection is based on predefined patterns and thresholds and may therefore produce false positives or miss novel attacks. The in-memory behavioral windows are not shared across multiple backend instances. Dashboard updates rely on polling rather than a push-based event channel. The prototype does not provide user authentication or fine-grained human-operator authorization for the dashboard. Request parameters are stored for traceability and would require systematic secret and personal-data redaction before production deployment. Formal performance benchmarks, adversarial stress testing, cryptographic log integrity, and distributed fault-tolerance evaluation remain outside the present scope." "Normal"

    Add-StyledParagraph $selection "6.4 Future Perspectives" "heading 2"
    Add-StyledParagraph $selection "Future work may introduce contextual ABAC conditions alongside RBAC, machine-learning-assisted anomaly detection, distributed rate-limit state, signed or append-only audit storage, secret redaction, operator authentication with least-privilege administrative roles, WebSocket-based event delivery, and stronger inter-agent trust mechanisms. Policy changes should remain separated from the ordinary supervision dashboard and should require a dedicated, authenticated, audited administrative workflow with version review and rollback." "Normal"

    # Refresh table of contents and all fields without changing the document theme.
    foreach ($toc in $doc.TablesOfContents) {
        $toc.Update()
    }
    $doc.Fields.Update() | Out-Null
    $doc.Save()
    $doc.Close()
}
finally {
    if ($null -ne $doc) {
        try { $doc.Close($false) } catch {}
    }
    $word.Quit()
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}
