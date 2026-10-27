"""FoxGuard Proje Kod İndirici.

GitHub deposundan (veya herhangi bir git remote'dan) proje kodunu indirir,
FoxGuard taramasına hazırlar. Kullanıcının GitHub kimlik doğrulaması (gh CLI)
zaten var olduğu için repoları listeleyip indirebilir.
"""

import os
import subprocess
import tempfile
import shutil
from datetime import datetime
from config import BASE_DIR


class ProjectDownloader:
    def __init__(self, download_dir: str = None):
        self.download_dir = download_dir or os.path.join(BASE_DIR, "downloaded_projects")
        os.makedirs(self.download_dir, exist_ok=True)

    def list_github_repos(self) -> list:
        """gh CLI ile kullanıcının GitHub repolarını listeler."""
        try:
            result = subprocess.run(
                ["gh", "repo", "list", "--limit", "100", "--json", "name,owner,url,defaultBranch"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return {"error": result.stderr.strip()}
            import json
            return json.loads(result.stdout)
        except FileNotFoundError:
            return {"error": "gh CLI bulunamadı. GitHub CLI kurulu olmalı."}
        except Exception as e:
            return {"error": str(e)}

    def download_repo(self, repo_full_name: str, branch: str = None) -> dict:
        """Bir GitHub deposunu indirir (klonlar)."""
        os.makedirs(self.download_dir, exist_ok=True)
        safe_name = repo_full_name.replace("/", "_")
        target = os.path.join(self.download_dir, safe_name)

        # Zaten varsa güncelle
        if os.path.exists(target) and os.path.exists(os.path.join(target, ".git")):
            try:
                subprocess.run(
                    ["git", "-C", target, "pull"],
                    capture_output=True, text=True, timeout=60,
                )
                return {"status": "updated", "path": target}
            except Exception as e:
                return {"error": f"Güncelleme hatası: {e}"}

        url = f"https://github.com/{repo_full_name}.git"
        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd += ["--branch", branch]
        cmd += [url, target]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                return {"error": result.stderr.strip()}
            return {"status": "downloaded", "path": target}
        except subprocess.TimeoutExpired:
            return {"error": "İndirme zaman aşımına uğradı."}
        except Exception as e:
            return {"error": str(e)}

    def download_zip(self, repo_full_name: str) -> dict:
        """Depoyu ZIP olarak indirir (daha hızlı, git geçmişi olmadan)."""
        import urllib.request
        os.makedirs(self.download_dir, exist_ok=True)
        url = f"https://github.com/{repo_full_name}/archive/refs/heads/main.zip"
        target_zip = os.path.join(self.download_dir, f"{repo_full_name.replace('/', '_')}.zip")
        try:
            urllib.request.urlretrieve(url, target_zip)
            extract_dir = os.path.join(self.download_dir, repo_full_name.replace("/", "_"))
            os.makedirs(extract_dir, exist_ok=True)
            shutil.unpack_archive(target_zip, extract_dir)
            os.remove(target_zip)
            return {"status": "downloaded", "path": extract_dir}
        except Exception as e:
            return {"error": str(e)}

    def list_downloaded(self) -> list:
        """İndirilen projeleri listeler."""
        if not os.path.exists(self.download_dir):
            return []
        items = []
        for name in os.listdir(self.download_dir):
            path = os.path.join(self.download_dir, name)
            if os.path.isdir(path):
                items.append({
                    "name": name,
                    "path": path,
                    "files": sum(len(files) for _, _, files in os.walk(path)),
                })
        return sorted(items, key=lambda x: x["name"])

    def scan_with_foxguard(self, project_path: str, scanner) -> dict:
        """İndirilen projeyi FoxGuard tarama motoruyla tarar."""
        return scanner.scan_path(project_path)


downloader = ProjectDownloader()
