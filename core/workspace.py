"""
SpiderFoot & Recon-ng Inspired Scan Workspace & Entity Graph Engine v6.0.

Provides workspace isolation, entity relationship mapping, and persistent asset tracking.

Graph Model:
  Target Domain ──► Subdomain ──► IP Address ──► Service
                     │
                     └──► Web Application ──► Endpoint ──► Parameter ──► Finding
"""

import json
import uuid
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime, timezone


@dataclass
class EntityNode:
    """Graph entity node representing a discovered target asset."""
    id: str
    entity_type: str  # Domain, Subdomain, IP, Service, Technology, Endpoint, Parameter, Finding
    value: str
    properties: Dict = field(default_factory=dict)
    parent_id: Optional[str] = None


class ScanWorkspace:
    """Isolated scan workspace maintaining attack surface entity graph and findings."""

    def __init__(self, workspace_name: str, target_url: str):
        self.workspace_id = uuid.uuid4().hex[:12]
        self.name = workspace_name
        self.target_url = target_url
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.nodes: Dict[str, EntityNode] = {}
        self._lock = threading.Lock()

        # Add root domain node
        root_node = EntityNode(
            id="root",
            entity_type="Domain",
            value=target_url,
            properties={"scan_start": self.created_at},
        )
        self.nodes["root"] = root_node

    def add_entity(self, entity_type: str, value: str, parent_id: str = "root", properties: dict = None) -> str:
        """Add an asset node to the workspace entity graph."""
        node_id = uuid.uuid5(uuid.NAMESPACE_URL, f"{entity_type}:{value}").hex[:12]
        with self._lock:
            if node_id not in self.nodes:
                node = EntityNode(
                    id=node_id,
                    entity_type=entity_type,
                    value=value,
                    properties=properties or {},
                    parent_id=parent_id,
                )
                self.nodes[node_id] = node
        return node_id

    def get_entities_by_type(self, entity_type: str) -> List[EntityNode]:
        with self._lock:
            return [n for n in self.nodes.values() if n.entity_type.lower() == entity_type.lower()]

    def export_graph_json(self) -> dict:
        """Serialize entity graph to JSON format."""
        with self._lock:
            return {
                "workspace_id": self.workspace_id,
                "name": self.name,
                "target": self.target_url,
                "created_at": self.created_at,
                "nodes": [
                    {
                        "id": n.id,
                        "type": n.entity_type,
                        "value": n.value,
                        "parent": n.parent_id,
                        "properties": n.properties,
                    }
                    for n in self.nodes.values()
                ]
            }
