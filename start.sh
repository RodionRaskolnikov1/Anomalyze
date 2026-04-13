#!/bin/bash
python -m app.scripts.seed
python -m app.scripts.run_training
uvicorn app.main:app --host 0.0.0.0 --port $PORT