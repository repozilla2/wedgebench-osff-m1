# WedgeBench M2 Reviewer Quickstart

## Purpose

This document explains how to run the current M2 `go-tcg-storage` reference integration.

M2 demonstrates that WedgeBench can connect to a real firmware-adjacent parser boundary while preserving:

- deterministic replay
- adapter-based integration
- machine-checkable draft artifacts
- parser outcome classification
- wedge field compatibility

## Current Target

`open-source-firmware/go-tcg-storage`

Boundary:

`plainCom.Receive(ses *Session)`

## Run Tests

```bash
python3 -m pytest tests/test_tcg_adapter_contract.py
