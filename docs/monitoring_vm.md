# Monitoring VM setup

This project assumes a lab network with:

- Kali attacker: `192.168.8.129`
- Ubuntu monitored VM: `192.168.8.133`
- VMware NAT network: `192.168.8.0/24`

Recommended architecture:

1. Build a dedicated Ubuntu monitoring VM.
2. Enable promiscuous mode or port mirroring on the VMware switch.
3. Run Suricata on the monitoring VM so it sees mirrored traffic instead of local loopback traffic.
4. Update the Suricata `af-packet` interface to the mirrored NIC.
5. Use `/var/log/suricata/eve.json` as the monitoring output source for the parser.

This avoids false positives caused by local traffic and better reflects a real network path.
