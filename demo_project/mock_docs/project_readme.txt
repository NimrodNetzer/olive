# ProjectX — Distributed Task Manager

## Overview
ProjectX is a lightweight distributed task management system built for small-to-medium teams.
It provides real-time task synchronization, deadline tracking, and team collaboration features.

## Architecture
- Backend:       Python FastAPI with PostgreSQL
- Frontend:      React + TypeScript
- Message Queue: Redis Streams
- Deployment:    Docker Compose

## Getting Started
1. Clone the repository
2. Copy `.env.example` to `.env` and fill in your values
3. Run `docker compose up`
4. Access the dashboard at http://localhost:3000

## API
The REST API is available at http://localhost:8080/api/v1
See api_notes.txt for full endpoint documentation.

## Contributing
Submit pull requests against the `main` branch.
All PRs require at least one reviewer approval and passing CI.

## License
MIT
