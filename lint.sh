#!/usr/bin/env bash

# backend
ruff format backend/
ruff check --fix backend/

# frontend
cd frontend
source ~/.nvm/nvm.sh
nvm use
npm run format
cd ..
