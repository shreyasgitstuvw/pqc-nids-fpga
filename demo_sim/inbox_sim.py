#!/usr/bin/env python3
"""demo_sim/inbox_sim.py -- kept for muscle memory: same as `chat_sim.py --me B`."""
import sys
sys.argv = [sys.argv[0], "--me", "B"]
import chat_sim
sys.exit(chat_sim.main())
