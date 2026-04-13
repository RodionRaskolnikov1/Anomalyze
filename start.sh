#!/bin/bash
python -m app.scripts.seed
python -m app.scripts.run_training
python -m app.scripts.backfill_detection &   
uvicorn app.main:app --host 0.0.0.0 --port $PORT