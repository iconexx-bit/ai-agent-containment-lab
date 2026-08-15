# Makefile — a SHIM. All logic lives in justfile + scripts/.
# ASCC convention: justfile is the single source of truth. This exists only so
# `make range-up` keeps working from muscle memory. Do not add logic here.

.DEFAULT_GOAL := help

help:
	@just --list

# forward every other target to just
%:
	@just $@

.PHONY: help
