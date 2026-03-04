# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for VlamGuard CLI standalone binary."""

import sys

block_cipher = None

a = Analysis(
    ["pyinstaller_entrypoint.py"],
    pathex=["src"],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Policy registry population (side-effect import)
        "vlamguard.engine.policies",
        # Pydantic v2 dynamic imports
        "pydantic",
        "pydantic.deprecated",
        "pydantic._internal",
        "pydantic._internal._generate_schema",
        "pydantic._internal._validators",
        "pydantic._internal._config",
        # JSON Schema validation
        "jsonschema",
        "jsonschema._format",
        "jsonschema._types",
        "jsonschema._utils",
        "jsonschema.validators",
        "jsonschema.protocols",
        "referencing",
        "referencing._core",
        "jsonschema_specifications",
        # Typer / Click internals
        "shellingham",
        # Runtime deps
        "dotenv",
        "yaml",
        "httpx",
        "anyio._backends._asyncio",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Server (Docker-only)
        "uvicorn",
        "fastapi",
        "starlette",
        "websockets",
        "uvloop",
        "httptools",
        "watchfiles",
        # Not imported in source
        "detect_secrets",
        # Dev-only
        "pytest",
        "coverage",
        "pip",
        "setuptools",
        "hatchling",
        "_pytest",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="vlamguard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=sys.platform != "win32",
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
