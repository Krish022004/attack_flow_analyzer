"""
Packet Capture Module
Parses pcap files and captures live network traffic
Converts packets to event format compatible with existing analyzers
"""

import threading
import queue
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path
from collections import defaultdict

# Initialize HTTP variables as None
HTTPRequest = None
HTTPResponse = None
HTTP_AVAILABLE = False

try:
    from scapy.all import rdpcap, sniff, IP, TCP, UDP, ICMP, DNS, Raw
    SCAPY_AVAILABLE = True
    # Try to import HTTP layers (optional, may not be available in all scapy versions)
    try:
        from scapy.layers.http import HTTPRequest, HTTPResponse
        HTTP_AVAILABLE = True
    except (ImportError, AttributeError):
        # HTTP layers not available, variables remain None
        pass
except ImportError as e:
    SCAPY_AVAILABLE = False
    print(f"Warning: scapy not available. Packet capture features will be limited. Error: {e}")


class PcapFileParser:
    """Parser for .pcap and .pcapng files"""
    
    def __init__(self):
        self.parsed_events = []
        self.errors = []
    
    def parse(self, pcap_file: Path) -> List[Dict]:
        """Parse pcap file and convert packets to events"""
        if not SCAPY_AVAILABLE:
            self.errors.append("scapy library not available")
            return []
        
        if not pcap_file.exists():
            self.errors.append(f"Pcap file not found: {pcap_file}")
            return []
        
        try:
            packets = rdpcap(str(pcap_file))
            events = []
            
            for packet in packets:
                event = self._packet_to_event(packet, pcap_file.name)
                if event:
                    events.append(event)
            
            self.parsed_events = events
            return events
            
        except Exception as e:
            self.errors.append(f"Error parsing pcap file {pcap_file}: {str(e)}")
            return []
    
    def _packet_to_event(self, packet, source_file: str) -> Optional[Dict]:
        """Convert a scapy packet to event dictionary"""
        try:
            # Extract timestamp
            timestamp = datetime.fromtimestamp(float(packet.time))
            
            # Initialize event
            event = {
                'timestamp': timestamp,
                'log_type': 'packet_capture',
                'log_source': source_file,
                'packet_size': len(packet),
                'protocol': 'unknown',
                'raw_data': {}
            }
            
            # Extract IP layer
            if IP in packet:
                ip_layer = packet[IP]
                event['source_ip'] = ip_layer.src
                event['destination_ip'] = ip_layer.dst
                # Convert protocol number to string (will be overwritten by specific protocol names)
                event['protocol'] = str(ip_layer.proto)
                
                # Extract transport layer (TCP/UDP)
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    event['source_port'] = tcp_layer.sport
                    event['destination_port'] = tcp_layer.dport
                    event['protocol'] = 'tcp'
                    event['raw_data']['tcp_flags'] = tcp_layer.flags
                    
                    # Extract HTTP if present (only if HTTP layers are available)
                    if HTTP_AVAILABLE:
                        try:
                            if HTTPRequest and HTTPRequest in packet:
                                http_layer = packet[HTTPRequest]
                                event['path'] = http_layer.Path.decode() if http_layer.Path else ''
                                event['method'] = http_layer.Method.decode() if http_layer.Method else ''
                                event['user_agent'] = http_layer.User_Agent.decode() if http_layer.User_Agent else ''
                                event['protocol'] = 'http'
                            elif HTTPResponse and HTTPResponse in packet:
                                http_layer = packet[HTTPResponse]
                                event['status_code'] = http_layer.Status_Code if hasattr(http_layer, 'Status_Code') else 0
                                event['protocol'] = 'http'
                        except (AttributeError, KeyError, TypeError):
                            # HTTP parsing failed, continue without HTTP data
                            pass
                    
                    # Extract payload
                    if Raw in packet:
                        payload = packet[Raw].load
                        event['payload'] = payload[:1000]  # Limit payload size
                        event['raw_data']['payload_size'] = len(payload)
                
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    event['source_port'] = udp_layer.sport
                    event['destination_port'] = udp_layer.dport
                    event['protocol'] = 'udp'
                    
                    # Extract DNS if present
                    if DNS in packet:
                        dns_layer = packet[DNS]
                        event['protocol'] = 'dns'
                        if dns_layer.qr == 0:  # Query
                            if dns_layer.qd:
                                event['raw_data']['dns_query'] = dns_layer.qd.qname.decode() if dns_layer.qd.qname else ''
                        else:  # Response
                            if dns_layer.an:
                                event['raw_data']['dns_answer'] = str(dns_layer.an[0].rdata) if dns_layer.an else ''
                    
                    # Extract payload
                    if Raw in packet:
                        payload = packet[Raw].load
                        event['payload'] = payload[:1000]
                        event['raw_data']['payload_size'] = len(payload)
                
                elif ICMP in packet:
                    icmp_layer = packet[ICMP]
                    event['protocol'] = 'icmp'
                    event['raw_data']['icmp_type'] = icmp_layer.type
                    event['raw_data']['icmp_code'] = icmp_layer.code
            
            else:
                # Non-IP packet
                return None
            
            return event
            
        except Exception as e:
            return None
    
    def get_statistics(self) -> Dict:
        """Get parsing statistics"""
        return {
            'total_events': len(self.parsed_events),
            'errors': len(self.errors),
            'error_messages': self.errors
        }


class LiveCapture:
    """Live network traffic capture"""
    
    def __init__(self, interface: Optional[str] = None, packet_count: int = 1000):
        self.interface = interface
        self.packet_count = packet_count
        self.captured_packets = []
        self.capture_thread: Optional[threading.Thread] = None
        self.capture_queue = queue.Queue()
        self.is_capturing = False
        self.stop_event = threading.Event()
        self.errors = []
        self.statistics = defaultdict(int)
    
    def start_capture(self, duration: Optional[int] = None, packet_callback: Optional[callable] = None) -> bool:
        """Start live packet capture in background thread
        
        Args:
            duration: Optional duration in seconds
            packet_callback: Optional callback function called with parsed packet event when packet is captured
        """
        if not SCAPY_AVAILABLE:
            self.errors.append("scapy library not available")
            return False
        
        if self.is_capturing:
            self.errors.append("Capture already in progress")
            return False
        
        self.is_capturing = True
        self.stop_event.clear()
        self.captured_packets = []
        self.statistics = defaultdict(int)
        self.packet_callback = packet_callback
        self.packet_counter = 0
        
        # Start capture in background thread
        self.capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(duration,),
            daemon=True
        )
        self.capture_thread.start()
        
        return True
    
    def _capture_worker(self, duration: Optional[int]):
        """Worker thread for packet capture"""
        try:
            packet_count = 0
            parser = PcapFileParser()
            
            # Log capture start
            interface_info = f"interface '{self.interface}'" if self.interface else "default interface"
            print(f"[Capture Worker] Starting packet capture on {interface_info}...")
            
            def packet_handler(packet):
                nonlocal packet_count
                if self.stop_event.is_set():
                    return False  # Signal to stop
                
                # Add to queue for later processing
                self.capture_queue.put(packet)
                
                # Parse packet immediately for real-time streaming
                if self.packet_callback:
                    try:
                        event = parser._packet_to_event(packet, "live_capture")
                        if event:
                            self.packet_counter += 1
                            event['packet_number'] = self.packet_counter
                            # Keep timestamp as datetime object - will be converted to ISO in callback for WebSocket
                            # This ensures events stored in captured_events have datetime objects for analysis
                            # Call callback with parsed packet event (callback will handle serialization)
                            if self.packet_callback:
                                try:
                                    self.packet_callback(event)
                                except Exception as callback_error:
                                    print(f"[Capture Worker] Error in packet callback: {callback_error}")
                                    import traceback
                                    traceback.print_exc()
                    except Exception as e:
                        # Log error but don't fail capture
                        import traceback
                        print(f"[Capture Worker] Error parsing packet for streaming: {e}")
                        traceback.print_exc()
                
                packet_count += 1
                # Stop if we've reached the packet count limit
                if packet_count >= self.packet_count:
                    print(f"[Capture Worker] Reached packet count limit ({self.packet_count}), stopping...")
                    self.stop_event.set()
                return True
            
            # Start sniffing
            sniff_kwargs = {
                'prn': packet_handler,
                'stop_filter': lambda x: self.stop_event.is_set(),
            }
            
            if self.interface:
                sniff_kwargs['iface'] = self.interface
                print(f"[Capture Worker] Using interface: {self.interface}")
            else:
                print(f"[Capture Worker] Using default interface (scapy will auto-detect)")
            
            if duration:
                sniff_kwargs['timeout'] = duration
                print(f"[Capture Worker] Capture will run for {duration} seconds")
            else:
                # If no duration, use count as limit
                sniff_kwargs['count'] = self.packet_count
                print(f"[Capture Worker] Capture will capture up to {self.packet_count} packets")
            
            print(f"[Capture Worker] Starting sniff()...")
            sniff(**sniff_kwargs)
            print(f"[Capture Worker] Sniff completed. Total packets captured: {packet_count}")
        except Exception as e:
            error_msg = f"Capture error: {str(e)}"
            self.errors.append(error_msg)
            print(f"[Capture Worker] ERROR: {error_msg}")
            import traceback
            traceback.print_exc()
        finally:
            self.is_capturing = False
            print(f"[Capture Worker] Capture worker finished. is_capturing = {self.is_capturing}")
    
    def stop_capture(self) -> List[Dict]:
        """Stop capture and return captured packets as events"""
        if not self.is_capturing:
            # If not capturing, return any previously captured packets
            return self.captured_packets
        
        self.stop_event.set()
        
        # Wait for capture thread to finish (with timeout)
        if self.capture_thread:
            self.capture_thread.join(timeout=10.0)
        
        # Process ALL queued packets
        events = []
        parser = PcapFileParser()
        processed_count = 0
        skipped_count = 0
        error_count = 0
        queue_size_before = self.capture_queue.qsize()
        
        # Process all packets in queue
        while True:
            try:
                packet = self.capture_queue.get_nowait()
                try:
                    event = parser._packet_to_event(packet, "live_capture")
                    if event:
                        # Ensure protocol is always a string for statistics
                        protocol = event.get('protocol', 'unknown')
                        if not isinstance(protocol, str):
                            protocol = str(protocol)
                            event['protocol'] = protocol
                        
                        events.append(event)
                        self.statistics[protocol] += 1
                        processed_count += 1
                    else:
                        # Event is None (non-IP packet or parsing failed silently)
                        skipped_count += 1
                except Exception as e:
                    error_count += 1
                    if len(self.errors) < 10:  # Limit error messages
                        self.errors.append(f"Error processing packet: {str(e)}")
            except queue.Empty:
                break
        
        self.captured_packets = events
        self.is_capturing = False
        
        # Log processing results for debugging
        if queue_size_before > 0:
            summary = f"Queue: {queue_size_before} packets, Processed: {processed_count}, Skipped: {skipped_count}, Errors: {error_count}"
            if error_count > 0 or processed_count == 0:
                self.errors.append(summary)
        
        return events
    
    def get_status(self) -> Dict:
        """Get current capture status"""
        # Convert statistics to ensure all keys are strings (JSON serialization requirement)
        stats_dict = {}
        for key, value in self.statistics.items():
            # Convert key to string if it's not already
            str_key = str(key) if not isinstance(key, str) else key
            stats_dict[str_key] = value
        
        return {
            'is_capturing': self.is_capturing,
            'packets_captured': len(self.captured_packets),
            'queued_packets': self.capture_queue.qsize(),
            'statistics': stats_dict,
            'errors': self.errors[-10:] if len(self.errors) > 10 else self.errors  # Limit error messages
        }
    
    def get_captured_events(self) -> List[Dict]:
        """Get captured packets as events"""
        return self.captured_packets

