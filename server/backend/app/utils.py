#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import yaml
import os
from functools import reduce
from typing import Any, Iterable, Iterator


CONFIG_PATH = "/usr/share/spyguard/config.yaml"
WATCHERS_PATH = "/usr/share/spyguard/watchers.yaml"


def read_config(path: Iterable[str], default: Any = None) -> Any:
    """
        Read a value from the configuration
        :return: value (it can be any type)
    """
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config = yaml.load(f, Loader=yaml.SafeLoader) or {}
    except Exception:
        return default

    cur: Any = config
    for key in path:
        if not isinstance(cur, dict):
            return default
        if key not in cur:
            return default
        cur = cur[key]
    return cur


def write_config(cat: str, key: str, value: Any) -> bool:
    """
        Write a new value in the configuration
        :return: bool, operation status
    """
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config = yaml.load(f, Loader=yaml.SafeLoader) or {}
        if not isinstance(config, dict):
            return False
        if cat not in config or not isinstance(config.get(cat), dict):
            return False
        config[cat][key] = value

        tmp_path = f"{CONFIG_PATH}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as yaml_file:
            yaml_file.write(yaml.dump(config, default_flow_style=False))
            yaml_file.flush()
            os.fsync(yaml_file.fileno())
        os.replace(tmp_path, CONFIG_PATH)
        return True
    except (OSError, yaml.YAMLError, KeyError, TypeError, ValueError):
        return False


def get_watchers(watcher_type: str) -> Iterator[dict[str, Any]]:
    """
        Read a value from the configuration
        :return: value (it can be any type)
    """
    with open(WATCHERS_PATH, "r", encoding="utf-8") as f:
        watchers = yaml.load(f, Loader=yaml.SafeLoader)
    for watcher in watchers["watchers"]:
        if watcher_type == watcher["type"]:
            yield watcher


def get_device_uuid() -> str:
    """Get the device UUID

    Returns:
        str: device uuid
    """

    uuid_not_found = False
    try:
        with open("/sys/class/dmi/id/product_uuid", "r") as uuid:
            return uuid.read()
    except:
        uuid_not_found = True

    try:
        with open("/proc/cpuinfo") as f:
            for line in f.readlines():
                if line.startswith("Serial"):
                    serial = line.split(":")[1].strip().encode('utf8')
                    hash = hashlib.md5(serial).hexdigest()
                    return f"{hash[0:8]}-{hash[8:12]}-{hash[12:16]}-{hash[16:20]}-{hash[20:]}"
    except:
        uuid_not_found = True
    
    if uuid_not_found:
        return "00000000-0000-0000-0000-000000000000"
