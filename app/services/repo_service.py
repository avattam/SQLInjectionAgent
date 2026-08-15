import os
import shutil
import tempfile
import git
from typing import Optional, Tuple

from app.services.secret_redactor import redact_secrets

class RepoService:
    def __init__(self, workspace_root: str):
        self.workspace_root = os.path.abspath(workspace_root)

    def prepare_repository(
        self,
        repo_url: Optional[str] = None,
        local_path: Optional[str] = None,
        branch: Optional[str] = "main"
    ) -> Tuple[str, str, bool]:
        """
        Prepares a target repository directory for scanning.
        Returns: (target_directory_path, repo_display_name, is_temporary)
        """
        if local_path:
            abs_local = os.path.abspath(local_path)
            if not os.path.exists(abs_local):
                raise FileNotFoundError(f"Local repository path does not exist: {local_path}")
            return abs_local, os.path.basename(abs_local), False

        if repo_url:
            # Clone remote repository safely into a temporary directory
            temp_dir = tempfile.mkdtemp(prefix="sql_agent_repo_")
            try:
                print(f"[RepoService] Cloning remote repo {repo_url} into {temp_dir}...")
                repo = git.Repo.clone_from(repo_url, temp_dir, branch=branch or "main", depth=1)
                repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
                return temp_dir, repo_name, True
            except Exception as e:
                # Clean up on failure
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
                raise RuntimeError(f"Failed to clone Git repository {redact_secrets(repo_url)}: {e}")

        # Default fallback: scan the workspace root itself
        return self.workspace_root, os.path.basename(self.workspace_root), False

    def create_security_branch(self, repo_dir: str, branch_name: str) -> bool:
        """
        Creates and checks out a new git security branch if the directory is a Git repository.
        """
        try:
            repo = git.Repo(repo_dir)
            if branch_name not in repo.branches:
                new_branch = repo.create_head(branch_name)
                new_branch.checkout()
            else:
                repo.branches[branch_name].checkout()
            return True
        except Exception as e:
            print(f"[RepoService] Note: Could not create Git branch {branch_name}: {e}")
            return False

    def cleanup_temp_repo(self, temp_dir: str):
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
                print(f"[RepoService] Cleaned up temporary directory {temp_dir}")
            except Exception as e:
                print(f"[RepoService] Cleanup error: {e}")
