"""
Zenith Session Manager - Save, Resume, and Manage scan sessions.
Never lose your progress again - sessions auto-save and can be resumed anytime.
"""

import json
import os
import time
import glob
from datetime import datetime


class SessionManager:
    """
    Manages scan sessions - save state, resume interrupted scans,
    and list previous sessions.
    """

    SESSIONS_DIR = os.path.expanduser("~/.zenith/sessions")

    def __init__(self):
        """Initialize session manager."""
        os.makedirs(self.SESSIONS_DIR, exist_ok=True)

    def create_session(self, target, goal, model, api_key_hash, max_iterations=100):
        """
        Create a new scan session.
        
        Args:
            target: Target URL/IP
            goal: Scanning goal
            model: AI model choice
            api_key_hash: Hashed API key (for identification, not storage)
            max_iterations: Max AI iterations
            
        Returns:
            str: Session ID
        """
        session_id = f"zenith_{int(time.time())}_{self._safe_name(target)}"
        
        session_data = {
            "session_id": session_id,
            "status": "running",
            "target": target,
            "goal": goal,
            "model": model,
            "api_key_hash": api_key_hash,
            "max_iterations": max_iterations,
            "current_iteration": 0,
            "current_phase": "recon",
            "phase_iteration": 0,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "last_command": "",
            "last_output": "",
            "working_dir": "",
            "ai_calls": 0,
            "commands_executed": 0,
            "commands_failed": 0,
            "vulnerabilities_found": 0,
            "chat_history": [],
            "knowledge_base_file": "",
        }
        
        self._save_session(session_id, session_data)
        return session_id

    def save_state(self, session_id, **kwargs):
        """
        Save current scan state to session.
        
        Args:
            session_id: Session ID
            **kwargs: State fields to update (iteration, phase, last_command, etc.)
        """
        session = self.load_session(session_id)
        if not session:
            return False
        
        session["updated_at"] = datetime.now().isoformat()
        
        for key, value in kwargs.items():
            if key in session:
                session[key] = value
        
        self._save_session(session_id, session)
        return True

    def load_session(self, session_id):
        """Load a session by ID."""
        session_file = os.path.join(self.SESSIONS_DIR, f"{session_id}.json")
        if not os.path.exists(session_file):
            return None
        
        try:
            with open(session_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, Exception):
            return None

    def mark_completed(self, session_id):
        """Mark a session as completed."""
        self.save_state(session_id, status="completed")

    def mark_interrupted(self, session_id):
        """Mark a session as interrupted (can be resumed)."""
        self.save_state(session_id, status="interrupted")

    def mark_failed(self, session_id, error=""):
        """Mark a session as failed."""
        session = self.load_session(session_id)
        if session:
            session["status"] = "failed"
            session["error"] = error
            session["updated_at"] = datetime.now().isoformat()
            self._save_session(session_id, session)

    def list_sessions(self, limit=20):
        """
        List all saved sessions, newest first.
        
        Returns:
            list: List of session summaries
        """
        sessions = []
        pattern = os.path.join(self.SESSIONS_DIR, "zenith_*.json")
        
        for session_file in sorted(glob.glob(pattern), reverse=True)[:limit]:
            try:
                with open(session_file, 'r') as f:
                    data = json.load(f)
                sessions.append({
                    "session_id": data.get("session_id", ""),
                    "target": data.get("target", ""),
                    "status": data.get("status", "unknown"),
                    "model": data.get("model", ""),
                    "phase": data.get("current_phase", ""),
                    "iteration": data.get("current_iteration", 0),
                    "vulns": data.get("vulnerabilities_found", 0),
                    "created": data.get("created_at", ""),
                    "updated": data.get("updated_at", ""),
                })
            except (json.JSONDecodeError, Exception):
                continue
        
        return sessions

    def get_resumable_sessions(self):
        """Get sessions that can be resumed (interrupted or running)."""
        all_sessions = self.list_sessions(limit=50)
        return [s for s in all_sessions if s["status"] in ("interrupted", "running")]

    def delete_session(self, session_id):
        """Delete a session file."""
        session_file = os.path.join(self.SESSIONS_DIR, f"{session_id}.json")
        if os.path.exists(session_file):
            os.remove(session_file)
            return True
        return False

    def cleanup_old_sessions(self, days=30):
        """Remove sessions older than N days."""
        cutoff = time.time() - (days * 86400)
        cleaned = 0
        
        pattern = os.path.join(self.SESSIONS_DIR, "zenith_*.json")
        for session_file in glob.glob(pattern):
            if os.path.getmtime(session_file) < cutoff:
                os.remove(session_file)
                cleaned += 1
        
        return cleaned

    def _save_session(self, session_id, data):
        """Save session data to file."""
        session_file = os.path.join(self.SESSIONS_DIR, f"{session_id}.json")
        try:
            with open(session_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"    [!] Failed to save session: {e}")

    @staticmethod
    def _safe_name(target):
        """Create a safe filename from target."""
        import re
        safe = re.sub(r'[^a-zA-Z0-9]', '_', target)
        return safe[:30]

    @staticmethod
    def hash_api_key(api_key):
        """Create a non-reversible hash of API key for identification."""
        import hashlib
        return hashlib.sha256(api_key.encode()).hexdigest()[:16]
