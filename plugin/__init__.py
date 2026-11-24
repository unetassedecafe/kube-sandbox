"""Hermes terminal backend plugin: run every command in a kube micro-VM (gVisor sandbox pod).

The provider is what ``terminal.backend: kube-sandbox`` resolves to. Dispatch is structural, not a
prompt rule: the terminal tool, ``execute_code`` and the file tools all build their environment
through ``create_environment``, so nothing the model writes can run on the Hermes host.
"""

from __future__ import annotations

import logging
import os
import sys
import re
import shlex
import shutil
import subprocess
import threading
import time
import uuid

from agent.terminal_env_provider import TerminalEnvironmentProvider
from tools.environments.base import BaseEnvironment
from tools.environments.base_output import _ThreadedProcessHandle

log = logging.getLogger(__name__)

NAME = "kube-sandbox"
DEFAULT_HOME = "/root"


def _cfg(*keys, default=None):
    """Read ``terminal.*`` from the live config without caching it: settings change between turns."""
    try:
        from hermes_cli.config import cfg_get, load_config_readonly

        override = os.environ.get("HERMES_TERMINAL_" + "_".join(k.upper() for k in keys))
        if override:
            return override
        return cfg_get(load_config_readonly(), "terminal", *keys, default=default)
    except Exception:
        return default


def _kubesandbox_pkg():
    # The loader imports this file as hermes_plugins.<slug> with __path__ = plugin dir.
    # Try the relative import first (works when the loader sets __path__), then fall back
    # to loading the sibling package by file path for loaders that only set __package__.
    try:
        from . import kubesandbox  # type: ignore[no-redef]
        return kubesandbox
    except ImportError:
        import importlib.util
        pkg_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kubesandbox")
        spec = importlib.util.spec_from_file_location(
            "kube_sandbox_kubesandbox", os.path.join(pkg_dir, "__init__.py"),
            submodule_search_locations=[pkg_dir])
        mod = importlib.util.module_from_spec(spec)
        mod.__path__ = [pkg_dir]
        sys.modules["kube_sandbox_kubesandbox"] = mod
        spec.loader.exec_module(mod)
        return mod


def _sandbox_client(timeout: float = 30.0):
    kubesandbox = _kubesandbox_pkg()
    resolve_kubeconfig = kubesandbox.resolve_kubeconfig
    SandboxClient = kubesandbox.SandboxClient

    kubeconfig = _cfg("kubeconfig") or _cfg("kube_sandbox_kubeconfig") or os.environ.get("KUBECONFIG")
    context = _cfg("kube_sandbox_context") or None
    client = resolve_kubeconfig(kubeconfig, context) if kubeconfig else _in_cluster_client()
    return SandboxClient(
        client,
        namespace=_cfg("kube_sandbox_namespace", default="sandboxes") or "sandboxes",
        template=_cfg("kube_sandbox_template", default="dev") or "dev",
        container=_cfg("kube_sandbox_container", default="dev") or "dev",
        start_timeout=float(_cfg("kube_sandbox_start_timeout", default=180) or 180),
    )


def _in_cluster_client():
    """The pod's own service account: the only credential path that needs nothing on disk."""
    kubesandbox = _kubesandbox_pkg()
    ApiError, KubeClient = kubesandbox.ApiError, kubesandbox.KubeClient

    base = "/var/run/secrets/kubernetes.io/serviceaccount"
    if not os.path.exists(f"{base}/token"):
        raise ApiError(0, "no kubeconfig for the sandbox cluster: set terminal.kubeconfig or run in-cluster "
                          "(the mocha sandboxes app grants the hermes service account the sbx role)")
    return KubeClient(server="https://kubernetes.default.svc", ca_pem=open(f"{base}/ca.crt", "rb").read(),
                      token_file=f"{base}/token")


# The core's poll command names its three files this way (``/tmp/hermes_bg_<session>.{pid,log,exit}``).
def _kubectl_available() -> bool:
    return bool(shutil.which(_cfg("kube_sandbox_kubectl", default="kubectl") or "kubectl"))


class KubeSandboxEnvironment(BaseEnvironment):
    """One micro-VM (a claimed warm-pool pod), plus its teardown.

    Subclasses ``BaseEnvironment`` for the CWD tracking, snapshot sourcing and shell wrapper that
    every backend shares; only the spawn is ours: an exec stream into the pod instead of a local
    process.
    """

    # cleanup() destroys the VM, so its background commands are gone with it.
    cleanup_stops_processes = True

    def __init__(self, *, cwd: str, timeout: int, task_id: str, image: str = "", client_factory=None,
                 persistent: bool = False):
        self.task_id = task_id
        self.image = image
        self.persistent = persistent
        self._client_factory = client_factory or _sandbox_client
        self._client = None
        self._claim = None
        self._lock = threading.Lock()
        # Hermes passes ``~`` when default_cwd is a tilde: resolve it to this sandbox's home here, since
        # ``cd ~`` inside the pod would follow the pod's own HOME whatever the config says.
        super().__init__(cwd=self.home if cwd in ("", "~", None) else cwd, timeout=timeout)

    # -- cluster plumbing --------------------------------------------------
    def client(self):
        if self._client is None:  # always first built under the claim's lock
            self._client = self._client_factory()
        return self._client

    def claim(self):
        """Create or reuse this task's claim. Lazy: a session that never runs a command pays nothing."""
        with self._lock:
            if self._claim is not None:
                return self._claim
            self._claim = self.client().create(self.task_id or "default")
            log.info("kube-sandbox: claim %s -> pod %s", self._claim.name, self._claim.sandbox)
            self._seed_secrets()
            return self._claim

    @property
    def home(self) -> str:
        return _cfg("kube_sandbox_home", default=DEFAULT_HOME) or DEFAULT_HOME

    # -- spawn -------------------------------------------------------------
    def _run_bash(self, cmd_string: str, *, login: bool = False, timeout: int = 120,
                  stdin_data: str | None = None):
        """Run one wrapped script in the pod, in a worker thread behind the ProcessHandle the base waits on."""
        claim = self.claim()
        script = cmd_string
        argv = ["bash", "-l", "-c", script] if login else ["bash", "-c", script]
        data = stdin_data.encode() if stdin_data is not None else None

        def run() -> tuple[str, int]:
            out, rc = self.client().exec(claim, argv, timeout=float(timeout), stdin_data=data)
            return out.decode("utf-8", "replace"), int(rc)

        return _ThreadedProcessHandle(run)

    def _seed_secrets(self):
        """Write opt-in secret files into the VM from pod env vars — never into the sandbox env.

        ``terminal.kube_sandbox_secret_files`` is a list of maps, e.g.::

            terminal:
              kube_sandbox_secret_files:
                - path: /root/.git-credentials      # target file inside the micro-VM
                  env: GH_TOKEN                      # source: env var of the *Hermes* pod (from a k8s secret)
                  mode: 0600                         # optional, default 0600
                - path: /root/.npmrc
                  env: NPM_TOKEN

        The value is base64-carried through a single exec script and lands only in the target
        file; it never appears in the sandbox's environment or in any process argv.
        """
        entries = _cfg("kube_sandbox_secret_files", default=None) or []
        if isinstance(entries, dict):
            entries = [{"path": k, "env": v} for k, v in entries.items()]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            path, env_name = entry.get("path"), entry.get("env")
            if not path or not env_name:
                continue
            value = os.environ.get(str(env_name))
            if not value:
                log.warning("kube-sandbox: secret env %s not set in Hermes pod; skipping %s", env_name, path)
                continue
            mode = int(str(entry.get("mode", "0600")), 8)
            try:
                self.client().write_secret_file(self._claim, path=str(path), content=value, mode=mode)
                log.info("kube-sandbox: secret file %s seeded from env %s (mode %o)", path, env_name, mode)
            except Exception as exc:
                log.warning("kube-sandbox: seeding %s failed: %s", path, exc)
        # Back-compat: the old git-specific keys map to the generic mechanism.
        token = _cfg("kube_sandbox_git_token") or os.environ.get("KUBE_SANDBOX_GIT_TOKEN")
        if token:
            user = _cfg("kube_sandbox_git_user", default="unetassedecafe") or "unetassedecafe"
            host = _cfg("kube_sandbox_git_host", default="github.com") or "github.com"
            try:
                self.client().seed_git_credentials(self._claim, username=user, token=token, host=host)
                log.info("kube-sandbox: git credentials seeded for %s@%s (file-only)", user, host)
            except Exception as exc:
                log.warning("kube-sandbox: git credential seeding skipped: %s", exc)

    @property
    def home(self) -> str:
        return _cfg("kube_sandbox_home", default=DEFAULT_HOME) or DEFAULT_HOME

    # -- teardown ----------------------------------------------------------
    def cleanup(self):
        """Destroy the VM. Already gone is success; a claim that may still be alive raises."""
        claim = self._claim
        if claim is None or self._client is None:
            return
        try:
            self._client.remove(claim.name)
            self._claim = None
        except Exception as exc:
            raise RuntimeError(f"sandbox claim {claim.name} may still be alive: {exc}") from exc


class KubeSandboxProvider(TerminalEnvironmentProvider):
    name = NAME
    display_name = "Kube Sandbox (micro-VM)"
    is_remote = True
    is_container = True
    skip_container_guards = False
    session_isolated_when_nonpersistent = True

    @property
    def description(self) -> str:
        return "Run commands in a gVisor micro-VM claimed from the cluster's warm pool."

    @property
    def cache_path_base(self) -> str | None:
        return None

    @property
    def strip_env_keys(self) -> frozenset:
        return frozenset({"KUBECONFIG", "GITOPS_TOKEN", "SBX_KUBECONFIG"})

    @property
    def default_cwd(self) -> str:
        return _cfg("kube_sandbox_home", default=DEFAULT_HOME) or DEFAULT_HOME

    def is_available(self) -> bool:
        """Cheap and network-free: a kubeconfig (or the pod's own token) plus a kubectl for doctor."""
        if _cfg("kubeconfig") or _cfg("kube_sandbox_kubeconfig") or os.environ.get("KUBECONFIG"):
            return os.path.exists(str(_cfg("kubeconfig") or _cfg("kube_sandbox_kubeconfig")
                                      or os.environ.get("KUBECONFIG", "")))
        return os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token")

    def probe(self) -> tuple[str, str]:
        if not self.is_available():
            return "needs_setup", "No kubeconfig and no in-cluster service account token."
        return "ready", ""

    def doctor_checks(self) -> list[tuple[bool, str, str]]:
        checks: list[tuple[bool, str, str]] = [(self.is_available(), "kube-sandbox credentials",
                                                "(in-cluster token)" if os.path.exists(
                                                    "/var/run/secrets/kubernetes.io/serviceaccount/token")
                                                else "(kubeconfig)")]
        if _kubectl_available():
            checks.append((True, "kube-sandbox API reachability", self._api_check()))
        else:
            checks.append((False, "kube-sandbox API reachability",
                           "kubectl not on PATH (used by hermes doctor only; the backend speaks the API "
                           "directly with hermes_yaml + the kubeconfig)"))
        return checks

    def _api_check(self) -> str:
        kubectl = _cfg("kube_sandbox_kubectl", default="kubectl") or "kubectl"
        args = [kubectl, "version", "--request-timeout=5s", "-o", "json"]
        kubeconfig = _cfg("kubeconfig") or _cfg("kube_sandbox_kubeconfig")
        if kubeconfig:
            args[1:1] = ["--kubeconfig", str(kubeconfig)]
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return f"kubectl failed: {exc}"
        return "server reachable" if proc.returncode == 0 else (proc.stderr.strip() or "unreachable")[:200]

    def create_environment(self, *, cwd: str, timeout: int, task_id: str = "default",
                           image: str | None = None, container_config: dict | None = None, **kwargs):
        """``**kwargs`` is part of the plugin contract: unknown keys are ignored, never rejected."""
        task = task_id if task_id and task_id != "default" else f"ks-{uuid.uuid4().hex[:8]}"
        override = (image or "").strip()
        persistent = bool((container_config or {}).get("container_persistent"))
        return KubeSandboxEnvironment(cwd=cwd, timeout=timeout, task_id=task, image=override,
                                      persistent=persistent)


def register(ctx) -> None:
    """Plugin entry point: register the terminal backend under ``terminal.backend: kube-sandbox``."""
    ctx.register_terminal_environment_provider(KubeSandboxProvider())
