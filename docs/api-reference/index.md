# API Reference

## Coordinator Service API

### GET /api/v1/status
Returns the current status of the coordinator service.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2023-10-01T10:00:00Z",
  "active_analyzers": 3,
  "pending_jobs": 5
}
```

### POST /api/v1/analyze
Starts a new analysis job.

**Request Body:**
```json
{
  "target_url": "https://example.com",
  "target_type": "web2",
  "analysis_depth": "full",
  "auth_session": "session_data_here"
}
```

**Response:**
```json
{
  "job_id": "abc123",
  "status": "submitted",
  "estimated_completion": "2023-10-01T11:00:00Z"
}
```

### GET /api/v1/job/{job_id}
Gets the status and results of a specific job.

**Response:**
```json
{
  "job_id": "abc123",
  "status": "completed",
  "results": {
    "high_severity": 2,
    "medium_severity": 5,
    "low_severity": 10,
    "findings": [...]
  }
}
```

## Analyzer Service APIs

### Web2 Analyzer
#### POST /analyze/web2
Analyzes a web application.

**Request Body:**
```json
{
  "url": "https://example.com",
  "auth_session": "session_data",
  "max_depth": 3,
  "user_agent": "BugHunter/1.0"
}
```

### Web3 Analyzer
#### POST /analyze/web3
Analyzes a web3/dapp application.

**Request Body:**
```json
{
  "contract_address": "0x...",
  "rpc_endpoint": "https://...",
  "abi": "contract_abi_here"
}
```

### Android Analyzer
#### POST /analyze/android
Analyzes an Android APK.

**Request Body:**
```json
{
  "apk_url": "https://...",
  "sha256": "hash_of_apk"
}
```

### Desktop Analyzer
#### POST /analyze/desktop
Analyzes a desktop application.

**Request Body:**
```json
{
  "binary_url": "https://...",
  "platform": "linux|windows|macos"
}
```

## Scanner Service API

### POST /scan
Performs a security scan on provided data.

**Request Body:**
```json
{
  "target_data": "data_to_scan",
  "scan_types": ["sast", "dast", "secret"],
  "ruleset": "default"
}
```

## Reporter Service API

### GET /report/{job_id}
Generates a security report for a completed job.

**Response:**
```json
{
  "report_id": "rep123",
  "job_id": "abc123",
  "generated_at": "2023-10-01T10:30:00Z",
  "vulnerabilities": [...],
  "recommendations": [...]
}
```