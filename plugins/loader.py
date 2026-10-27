"""FoxGuard WordPress benzeri eklenti yükleyicisi.

Eklenti yapısı:
  plugins/<eklenti_adi>/
    ├── manifest.json   # Eklenti tanımı (isim, versiyon, açıklama, yetkiler)
    ├── __init__.py     # Eklenti giriş noktası (register() fonksiyonu)
    └── ...             # Diğer dosyalar

Hook sistemi (WordPress action/filter benzetimi):
  - register_hook(hook_name, callback)  -> bir olaya abone olur
  - run_hook(hook_name, *args, **kwargs) -> aboneleri çağırır
"""

import os
import json
import importlib
from typing import Dict, List, Callable, Any

PLUGINS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))


class PluginError(Exception):
    pass


class PluginLoader:
    def __init__(self, plugins_dir: str = PLUGINS_DIR):
        self.plugins_dir = plugins_dir
        self.plugins: Dict[str, dict] = {}
        self.hooks: Dict[str, List[Callable]] = {}
        self._loaded = False

    def discover(self) -> List[str]:
        """Eklenti klasörlerini tarar ve geçerli eklenti isimlerini döndürür."""
        if not os.path.exists(self.plugins_dir):
            return []
        found = []
        for name in os.listdir(self.plugins_dir):
            plugin_path = os.path.join(self.plugins_dir, name)
            manifest = os.path.join(plugin_path, "manifest.json")
            init_file = os.path.join(plugin_path, "__init__.py")
            if os.path.isdir(plugin_path) and os.path.exists(manifest) and os.path.exists(init_file):
                found.append(name)
        return sorted(found)

    def load_manifest(self, name: str) -> dict:
        with open(os.path.join(self.plugins_dir, name, "manifest.json"), "r", encoding="utf-8") as f:
            return json.load(f)

    def load_all(self) -> Dict[str, dict]:
        """Tüm eklentileri yükler."""
        self._loaded = True
        for name in self.discover():
            try:
                manifest = self.load_manifest(name)
                # Eklenti modülünü içe aktar
                module_path = f"plugins.{name}.__init__"
                mod = importlib.import_module(module_path)
                if hasattr(mod, "register"):
                    mod.register(self)
                self.plugins[name] = {
                    "manifest": manifest,
                    "module": mod,
                    "status": "active",
                }
            except Exception as e:
                self.plugins[name] = {
                    "manifest": {},
                    "module": None,
                    "status": f"error: {e}",
                }
        return self.plugins

    def register_hook(self, hook_name: str, callback: Callable):
        """Belirli bir kanca (hook) için geri çağrı kaydeder."""
        self.hooks.setdefault(hook_name, []).append(callback)

    def run_hook(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """Kancaya aboneli olan tüm fonksiyonları çalışır."""
        results = []
        for cb in self.hooks.get(hook_name, []):
            try:
                results.append(cb(*args, **kwargs))
            except Exception as e:
                results.append({"error": str(e)})
        return results

    def get_plugin(self, name: str) -> dict:
        return self.plugins.get(name, {})

    def list_plugins(self) -> List[dict]:
        return [
            {
                "name": name,
                "manifest": p.get("manifest", {}),
                "status": p.get("status", "unknown"),
            }
            for name, p in self.plugins.items()
        ]


# Global loader instance
loader = PluginLoader()
