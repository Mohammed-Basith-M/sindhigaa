"""
CyberShield Remediation Engine
Maps identified threat classifications and extracted packet evidence to prioritized mitigation playbooks.
Includes mandatory SOC environment validation disclaimers.
"""

from typing import List, Dict, Any

VALIDATION_DISCLAIMER = (
    "Important: These recommendations are based only on network evidence available in the analyzed PCAP. "
    "They should be validated against the actual network environment before taking action."
)

def generate_remediation(threat_result: Dict[str, Any], features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates actionable, prioritized remedial measures based on threat classification and evidence.
    """
    threat = threat_result.get("threat", "Benign")
    is_insufficient = threat_result.get("is_insufficient_evidence", False)
    is_benign = threat_result.get("is_benign", False)
    
    actions: List[Dict[str, Any]] = []
    
    if is_insufficient:
        return {
            "disclaimer": VALIDATION_DISCLAIMER,
            "actions": [],
            "insufficient_notice": "No specific remediation is recommended because the available PCAP evidence is insufficient to reliably identify a threat."
        }
        
    if is_benign:
        return {
            "disclaimer": VALIDATION_DISCLAIMER,
            "actions": [
                {
                    "priority": "LOW PRIORITY",
                    "action": "Maintain Routine Network Baseline Audits",
                    "reason": "Analyzed traffic conforms to normal operational profiles. Continue standard passive monitoring and flow telemetry aggregation."
                }
            ],
            "insufficient_notice": None
        }
        
    ports = features.get("unique_destination_ports", 0)
    summary = features.get("summary", {})
    pps = summary.get("packets_per_second", 0)
    
    if threat == "Port Scan":
        actions = [
            {
                "priority": "HIGH PRIORITY",
                "action": "Review Exposed Services & Restrict Unnecessary Ports",
                "reason": f"The analyzed traffic demonstrates active reconnaissance against {ports} unique ports. Enforce strict egress/ingress firewall policies."
            },
            {
                "priority": "HIGH PRIORITY",
                "action": "Implement State-Aware Rate Limiting & SYN Drop Rules",
                "reason": "Mitigate half-open scanning probes by configuring iptables/nftables to limit SYN connection attempt rates per source IP."
            },
            {
                "priority": "MEDIUM PRIORITY",
                "action": "Deploy Snort / Suricata Port-Scan Detection Signatures",
                "reason": "Enable automated threshold alerts (e.g. sfPortscan) to flag sequential port probes in real-time."
            },
            {
                "priority": "LOW PRIORITY",
                "action": "Audit Targeted Host for Rogue Services or Vulnerabilities",
                "reason": "Ensure targeted endpoint systems are not running unauthenticated administrative daemons."
            }
        ]
        
    elif threat == "DoS/DDoS":
        actions = [
            {
                "priority": "CRITICAL PRIORITY",
                "action": "Activate Edge Traffic Filtering & Upstream Rate Limiting",
                "reason": f"Sustained packet transmission velocities reaching {pps} packets/second threaten service availability."
            },
            {
                "priority": "HIGH PRIORITY",
                "action": "Enable SYN Cookies & TCP Connection Queue Protections",
                "reason": "Exhaustion of embryonic connection tables observed; SYN cookies prevent server backlog depletion."
            },
            {
                "priority": "HIGH PRIORITY",
                "action": "Engage Upstream Cloud / ISP DDoS Scrubbing Services",
                "reason": "Divert volumetric ingress traffic through upstream mitigation nodes before internal edge saturation."
            },
            {
                "priority": "MEDIUM PRIORITY",
                "action": "Isolate Affected Target Subnet Behind Protective Proxy",
                "reason": "Prevent collateral downtime on adjacent infrastructure sharing the target network segment."
            }
        ]
        
    elif threat == "Brute Force":
        actions = [
            {
                "priority": "HIGH PRIORITY",
                "action": "Enforce Multi-Factor Authentication (MFA) & Account Lockouts",
                "reason": "Repeated authentication connection attempts indicate automated dictionary and credential spraying."
            },
            {
                "priority": "HIGH PRIORITY",
                "action": "Deploy Fail2ban or Host-Based Login Rate Limiters",
                "reason": "Automatically drop IP addresses exceeding 5 failed authentication attempts within a 60-second window."
            },
            {
                "priority": "MEDIUM PRIORITY",
                "action": "Restrict Management Ports (SSH, RDP, SMB) Behind VPN",
                "reason": "Administrative services must not be exposed directly to untrusted public or perimeter segments."
            },
            {
                "priority": "MEDIUM PRIORITY",
                "action": "Audit Authentication Security Logs for Compromise",
                "reason": "Verify whether any repeated authentication sequences concluded with successful session establishment."
            }
        ]
        
    elif threat == "Possible Botnet/C2":
        actions = [
            {
                "priority": "HIGH PRIORITY",
                "action": "Quarantine & Isolate the Suspected Internal Endpoint",
                "reason": "Low-jitter periodic heartbeat patterns indicate active backdoor or trojan C2 channel establishment."
            },
            {
                "priority": "HIGH PRIORITY",
                "action": "Block External Destination IP / FQDN at Perimeter Firewall",
                "reason": "Prevent further exfiltration or tasking by severing connectivity to the command and control node."
            },
            {
                "priority": "HIGH PRIORITY",
                "action": "Conduct Deep Endpoint EDR & Process Memory Forensics",
                "reason": "Identify unauthorized background binaries, scheduled tasks, or injected threads maintaining persistence."
            },
            {
                "priority": "MEDIUM PRIORITY",
                "action": "Inspect DNS Query Logs for DGA (Domain Generation Algorithms)",
                "reason": "Detect dynamic fallback resolution mechanisms used by resilient botnet infrastructures."
            }
        ]
        
    elif threat == "Suspicious Connection":
        actions = [
            {
                "priority": "HIGH PRIORITY",
                "action": "Investigate & Terminate Unauthorized Listening Daemons",
                "reason": "Network traffic directly engaged known backdoor or exploitation listener ports."
            },
            {
                "priority": "HIGH PRIORITY",
                "action": "Block High-Risk Ports at Internal Core and Edge Firewalls",
                "reason": "Prevent reverse shell handshakes and remote exploit payload deliveries."
            },
            {
                "priority": "MEDIUM PRIORITY",
                "action": "Execute Antimalware / Rootkit Scans on Internal Host",
                "reason": "Verify file system integrity and check for unauthorized remote access trojans (RATs)."
            }
        ]
        
    else:
        actions = [
            {
                "priority": "MEDIUM PRIORITY",
                "action": "Review Anomaly Indicators & Deepen Packet Inspection",
                "reason": "Correlate observed deviation with host endpoint telemetry and firewall drop logs."
            }
        ]
        
    return {
        "disclaimer": VALIDATION_DISCLAIMER,
        "actions": actions,
        "insufficient_notice": None
    }
