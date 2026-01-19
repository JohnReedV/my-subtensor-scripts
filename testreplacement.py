#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ENV-gate regression test for txpool replace_previous()

This test asserts your new feature toggle is honored:

    SUBSTRATE_TXPOOL_ENABLE_REPLACE_PREVIOUS == "1"
        => replace_previous() RUNS
        => submitting a same-(signer, nonce) tx2 triggers replacement logic
        => with Subtensor’s constant priority, tx2 is rejected with:
             code=1014, message contains "Priority is too low"

    SUBSTRATE_TXPOOL_ENABLE_REPLACE_PREVIOUS == "0"
        => replace_previous() is SKIPPED (early return Ok(([],[])))
        => submitting the same-(signer, nonce) tx2 does NOT go through the
           replacement-path error, and (in your current node behavior) it is ACCEPTED.

So the assertions are:

  ENV=1: tx2 must fail with 1014 "Priority is too low"
  ENV=0: tx2 must be accepted (NOT 1014)

No flags / just run it:
  - Starts an isolated helper node twice (ENV=1 then ENV=0) on random ports.
  - Auto-detects your node-subtensor binary and --chain arg from your already running localnet via /proc.
  - Does NOT touch/kill your running nodes.

Deps:
  pip install substrate-interface

Run:
  python3 ./testbypass.py
"""

import os
import socket
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from substrateinterface import Keypair, SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException

ENV_NAME = "SUBSTRATE_TXPOOL_ENABLE_REPLACE_PREVIOUS"


# ──────────────────────────────────────────────────────────────────────────────
# Small utilities
# ──────────────────────────────────────────────────────────────────────────────


def normalize_0x(h: str) -> str:
    h = (h or "").strip()
    if not h.startswith("0x"):
        h = "0x" + h
    return h


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def read_cmd_output(cmd: List[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return out.decode("utf-8", errors="replace")
    except Exception:
        return ""


def has_flag(help_text: str, flag: str) -> bool:
    return flag in help_text


def tail_file(path: str, n_lines: int = 220) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read()
        lines = data.splitlines()[-n_lines:]
        return "\n".join(l.decode("utf-8", errors="replace") for l in lines)
    except Exception:
        return ""


# ──────────────────────────────────────────────────────────────────────────────
# /proc detection (Linux): find running node-subtensor + its --chain
# ──────────────────────────────────────────────────────────────────────────────


def iter_pids() -> List[int]:
    out: List[int] = []
    for name in os.listdir("/proc"):
        if name.isdigit():
            out.append(int(name))
    return out


def read_proc_cmdline(pid: int) -> List[str]:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
        if not raw:
            return []
        parts = raw.split(b"\x00")
        return [p.decode("utf-8", errors="replace") for p in parts if p]
    except Exception:
        return []


def read_proc_exe(pid: int) -> Optional[str]:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return None


def find_running_node_subtensor_bin_and_chain() -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (node_binary_path, chain_arg_value) if we detect a running node-subtensor.
    """
    for pid in iter_pids():
        cmd = read_proc_cmdline(pid)
        if not cmd:
            continue

        exe = read_proc_exe(pid)
        exe_base = os.path.basename(exe) if exe else ""
        cmd0_base = os.path.basename(cmd[0]) if cmd else ""

        if exe_base != "node-subtensor" and cmd0_base != "node-subtensor" and (
            "node-subtensor" not in " ".join(cmd)
        ):
            continue

        chain_val: Optional[str] = None
        for i, a in enumerate(cmd):
            if a.startswith("--chain="):
                chain_val = a.split("=", 1)[1]
                break
            if a == "--chain" and i + 1 < len(cmd):
                chain_val = cmd[i + 1]
                break

        bin_path = exe or cmd[0]
        if bin_path and os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
            return bin_path, chain_val

    return None, None


def find_node_binary() -> Tuple[str, Optional[str]]:
    # Optional env override
    for k in ("NODE_SUBTENSOR_BIN", "SUBTENSOR_NODE_BIN"):
        v = os.environ.get(k)
        if v and os.path.isfile(v) and os.access(v, os.X_OK):
            return v, None

    # Prefer running node path + chain
    b, c = find_running_node_subtensor_bin_and_chain()
    if b:
        return b, c

    # PATH fallback
    import shutil

    p = shutil.which("node-subtensor")
    if p:
        return p, None

    raise RuntimeError(
        "Could not locate node-subtensor.\n"
        "Either run your localnet (so /proc detection works), or set:\n"
        "  export NODE_SUBTENSOR_BIN=/path/to/node-subtensor\n"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Helper node (isolated, no block production required)
# ──────────────────────────────────────────────────────────────────────────────


def start_helper_node(
    node_bin: str,
    chain_arg: Optional[str],
    env_value: int,
) -> Tuple[subprocess.Popen, str, str]:
    help_text = read_cmd_output([node_bin, "--help"])

    ws_port = pick_free_port()
    rpc_port = pick_free_port()
    p2p_port = pick_free_port()

    argv: List[str] = [node_bin]

    # Use same chain spec if detected (so genesis accounts match your localnet)
    if chain_arg:
        argv += ["--chain", chain_arg]
    else:
        argv += ["--chain", "local"]

    if has_flag(help_text, "--tmp"):
        argv += ["--tmp"]

    # Keep it isolated so txs stay in the local pool
    if has_flag(help_text, "--no-mdns"):
        argv += ["--no-mdns"]
    if has_flag(help_text, "--in-peers"):
        argv += ["--in-peers", "0"]
    if has_flag(help_text, "--out-peers"):
        argv += ["--out-peers", "0"]
    if has_flag(help_text, "--port"):
        argv += ["--port", str(p2p_port)]

    # Unsafe RPC so author_submitExtrinsic is available
    if has_flag(help_text, "--rpc-methods"):
        argv += ["--rpc-methods", "Unsafe"]

    # Match your scripts' style
    if has_flag(help_text, "--rpc-cors"):
        argv += ["--rpc-cors=all"]

    # WS/RPC port differences
    if has_flag(help_text, "--ws-port"):
        argv += ["--ws-port", str(ws_port)]
        if has_flag(help_text, "--rpc-port"):
            argv += ["--rpc-port", str(rpc_port)]
    else:
        # some builds use --rpc-port for WS
        if not has_flag(help_text, "--rpc-port"):
            raise RuntimeError(
                "node-subtensor supports neither --ws-port nor --rpc-port; cannot run helper safely."
            )
        argv += ["--rpc-port", str(ws_port)]

    if has_flag(help_text, "--unsafe-force-node-key-generation"):
        argv += ["--unsafe-force-node-key-generation"]

    env = os.environ.copy()
    env[ENV_NAME] = str(env_value)

    log_path = f"/tmp/txpool_replace_previous_gate_env_{env_value}.log"
    log_f = open(log_path, "wb")

    proc = subprocess.Popen(
        argv,
        env=env,
        stdout=log_f,
        stderr=subprocess.STDOUT,
    )
    try:
        log_f.close()
    except Exception:
        pass

    ws_url = f"ws://127.0.0.1:{ws_port}"
    return proc, ws_url, log_path


def stop_node(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def wait_for_ws(ws_url: str, timeout_s: int = 45) -> SubstrateInterface:
    t0 = time.time()
    last_err: Optional[str] = None
    while time.time() - t0 < timeout_s:
        try:
            si = SubstrateInterface(url=ws_url)
            si.init_runtime()
            _ = si.rpc_request("system_health", [])
            return si
        except Exception as e:
            last_err = str(e)
            time.sleep(0.25)
    raise RuntimeError(f"Timed out waiting for WS {ws_url}. Last error: {last_err}")


# ──────────────────────────────────────────────────────────────────────────────
# Extrinsic helpers (raw author_submitExtrinsic with correct error handling)
# ──────────────────────────────────────────────────────────────────────────────


def compose_balances_transfer(si: SubstrateInterface, dest_ss58: str, value: int) -> object:
    for fn_name in ("transfer_keep_alive", "transfer"):
        try:
            return si.compose_call(
                call_module="Balances",
                call_function=fn_name,
                call_params={"dest": dest_ss58, "value": int(value)},
            )
        except Exception:
            continue
    raise RuntimeError("Could not compose Balances transfer call (transfer_keep_alive/transfer).")


def xt_to_hex(xt) -> str:
    if hasattr(xt, "data") and hasattr(xt.data, "to_hex"):
        return normalize_0x(xt.data.to_hex())
    if hasattr(xt, "to_hex"):
        return normalize_0x(xt.to_hex())
    raise RuntimeError("Could not convert extrinsic to hex.")


def author_submit(si: SubstrateInterface, xt_hex: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Returns (result_hash, error_dict).

    substrate-interface raises SubstrateRequestException when the RPC returns an error.
    We catch it and return the contained error dict.
    """
    xt_hex = normalize_0x(xt_hex)
    try:
        resp = si.rpc_request("author_submitExtrinsic", [xt_hex])
        if isinstance(resp, dict) and resp.get("error"):
            return None, resp["error"]
        if isinstance(resp, dict) and "result" in resp:
            return resp["result"], None
        return str(resp), None
    except SubstrateRequestException as e:
        if e.args and isinstance(e.args[0], dict):
            return None, e.args[0]
        return None, {"code": None, "message": str(e), "data": None}
    except Exception as e:
        return None, {"code": None, "message": str(e), "data": None}


def is_priority_too_low(err: Optional[Dict[str, Any]]) -> bool:
    if not err:
        return False
    return err.get("code") == 1014 and ("Priority is too low" in str(err.get("message") or ""))


# ──────────────────────────────────────────────────────────────────────────────
# The actual test cases
# ──────────────────────────────────────────────────────────────────────────────


def run_case(node_bin: str, chain_arg: Optional[str], env_value: int) -> Dict[str, Any]:
    proc, ws_url, log_path = start_helper_node(node_bin, chain_arg, env_value)
    try:
        print(f"\n=== CASE: {ENV_NAME}={env_value} ===")
        print(f"[i] Helper WS:  {ws_url}")
        print(f"[i] Helper log: {log_path}")

        si = wait_for_ws(ws_url)

        alice = Keypair.create_from_uri("//Alice")
        bob = Keypair.create_from_uri("//Bob")
        charlie = Keypair.create_from_uri("//Charlie")

        # Freeze nonce BEFORE tx1 so tx2 uses the exact same nonce.
        nonce = si.get_account_nonce(alice.ss58_address)

        call1 = compose_balances_transfer(si, bob.ss58_address, 1)
        call2 = compose_balances_transfer(si, charlie.ss58_address, 1)

        tx1 = si.create_signed_extrinsic(call=call1, keypair=alice, nonce=int(nonce), era="00", tip=0)
        tx2 = si.create_signed_extrinsic(call=call2, keypair=alice, nonce=int(nonce), era="00", tip=0)

        print("[i] Submitting tx1 (seed collision)")
        r1, e1 = author_submit(si, xt_to_hex(tx1))
        if e1:
            raise RuntimeError(
                f"tx1 unexpectedly failed: {e1}\n"
                f"log tail:\n{tail_file(log_path)}"
            )
        print(f"[✓] tx1 accepted: {r1}")

        # Small delay so tx1 is definitely in the pool before tx2 hits.
        time.sleep(0.35)

        print("[i] Submitting tx2 (same signer+nonce)")
        r2, e2 = author_submit(si, xt_to_hex(tx2))

        if e2:
            print(f"[i] tx2 rejected with error: {e2}")
        else:
            print(f"[i] tx2 accepted: {r2}")

        return {
            "env": env_value,
            "tx1_hash": r1,
            "tx2_hash": r2,
            "tx2_error": e2,
            "tx2_is_priority_too_low": is_priority_too_low(e2),
            "log_path": log_path,
        }

    finally:
        stop_node(proc)


def main() -> int:
    node_bin, chain_arg = find_node_binary()
    print(f"[i] Using node binary: {node_bin}")
    if chain_arg:
        print(f"[i] Detected running --chain: {chain_arg}")
    else:
        print("[i] No running --chain detected; helper will use '--chain local'.")

    # ENV=1: replacement logic runs => tx2 must be rejected via TooLowPriority
    res_on = run_case(node_bin, chain_arg, env_value=1)

    # ENV=0: replacement logic skipped => tx2 should be accepted (what you observed)
    res_off = run_case(node_bin, chain_arg, env_value=0)

    # ── Assertions ─────────────────────────────────────────────────────────────
    # ENV=1 must clearly show the replacement path ran:
    if not res_on["tx2_error"] or not res_on["tx2_is_priority_too_low"]:
        raise AssertionError(
            "FAIL: ENV=1 should trigger replacement path and reject tx2 with 1014 "
            "'Priority is too low'.\n"
            f"Got: {res_on['tx2_error']}\n"
            f"log tail:\n{tail_file(res_on['log_path'])}"
        )

    # ENV=0 must clearly show the replacement path did NOT run:
    # In your node behavior this means tx2 gets accepted.
    if res_off["tx2_error"] is not None:
        raise AssertionError(
            "FAIL: ENV=0 expected tx2 to be accepted (replacement path skipped), "
            "but it was rejected.\n"
            f"Got: {res_off['tx2_error']}\n"
            f"log tail:\n{tail_file(res_off['log_path'])}"
        )
    if res_off["tx2_is_priority_too_low"]:
        raise AssertionError(
            "FAIL: ENV=0 should NOT produce 1014 'Priority is too low' because replace_previous() "
            "is gated off.\n"
            f"Got: {res_off['tx2_error']}\n"
            f"log tail:\n{tail_file(res_off['log_path'])}"
        )

    print("\n✅ PASS: ENV gate is working exactly as your change intends.")
    print(f"    ENV=1 -> tx2 rejected with TooLowPriority (replace_previous ran): {res_on['tx2_error']}")
    print(f"    ENV=0 -> tx2 accepted (replace_previous skipped): {res_off['tx2_hash']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
