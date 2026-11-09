"""Linux Git settings, including root-run private snapshot protection."""
# Git diff can refresh its index even when optional locks are disabled. Under
# root, mode 0500 alone cannot stop creation of index.lock in a sealed copy.
# Disable that refresh; the existing before/after snapshot checks stay intact.
EXTRA_ARGS = ['-c', 'diff.autoRefreshIndex=false']
