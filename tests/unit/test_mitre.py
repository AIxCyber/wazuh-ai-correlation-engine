from src.scoring.mitre import MitreMapper


def test_map_event_type_brute_force():
    mapper = MitreMapper()
    result = mapper.map_event_type("brute_force")
    assert result["technique_id"] == "T1110"
    assert result["technique"] == "Brute Force"
    assert result["tactic"] == "Credential Access"


def test_map_event_type_malware():
    mapper = MitreMapper()
    result = mapper.map_event_type("malware")
    assert result["technique_id"] == "T1204"


def test_map_event_type_unknown():
    mapper = MitreMapper()
    result = mapper.map_event_type("unknown_type")
    assert result["technique_id"] == "T1078"  # default


def test_map_rule_id():
    mapper = MitreMapper()
    result = mapper.map_rule_id("5710")
    assert result is not None
    assert result["technique_id"] == "T1110"


def test_map_rule_id_unknown():
    mapper = MitreMapper()
    result = mapper.map_rule_id("99999")
    assert result is None


def test_map_incident_with_event_types():
    mapper = MitreMapper()
    incident = {
        "event_types": ["brute_force", "malware"],
        "alerts": [],
    }
    result = mapper.map_incident(incident)
    assert "mitre_mapping" in result
    assert len(result["mitre_mapping"]) == 2
    assert result["mitre_technique_id"] == "T1110"


def test_map_incident_without_event_types():
    mapper = MitreMapper()
    incident = {
        "event_types": [],
        "alerts": [
            {"event_type": "lateral_movement", "host": "h1"},
        ],
    }
    result = mapper.map_incident(incident)
    assert len(result["mitre_mapping"]) >= 1
    assert result["mitre_technique"] == "Remote Services"
