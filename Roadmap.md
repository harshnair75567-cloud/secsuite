FIM tamper-evident logging: Blockchain-based approach for FIM — either a Merkle tree or a rotating log that compresses 7 days of data — to make the file integrity manifest/audit history tamper-evident rather than a plain flat log.


Dead hand system: A dead-hand failsafe built on btrfs snapshots — if no check-in ("hand") is given within a 4-hour window, secsuite automatically reverts the system to the btrfs snapshot taken 4 hours prior. The check-in itself is a sudo command gated by the admin password (used as a stand-in for biometric confirmation, since no fingerprint scanner is available), which resets the timer each time it's run.
