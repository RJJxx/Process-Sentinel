# Project Architecture

The project follows a modular architecture.

Windows
    ↓
Process Monitor
    ↓
Process Analyzer
    ↓
Detection Rules
    ↓
Risk Engine
    ↓
Logger
    ↓
Report Generator
    ↓
GUI

Each module has a single responsibility.

Modules communicate using dictionaries.

Detection rules are independent and reusable.