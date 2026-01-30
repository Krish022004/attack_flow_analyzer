"""
IOC Exporter
Exports IOCs in multiple formats (JSON, CSV)
"""

import json
import csv
from typing import Dict, List
from pathlib import Path
from datetime import datetime


class IOCExporter:
    """Exports IOCs in various formats"""
    
    def __init__(self, iocs: Dict[str, Dict]):
        self.iocs = iocs
    
    def export_json(self, output_path: Path) -> bool:
        """Export IOCs to JSON format"""
        try:
            # Prepare data structure
            export_data = {
                'metadata': {
                    'export_time': datetime.now().isoformat(),
                    'total_iocs': len(self.iocs),
                    'format_version': '1.0',
                },
                'iocs': list(self.iocs.values()),
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            return True
        except Exception as e:
            print(f"Error exporting JSON: {e}")
            return False
    
    def export_csv(self, output_path: Path) -> bool:
        """Export IOCs to CSV format"""
        try:
            if not self.iocs:
                return False
            
            # Get all unique fields
            all_fields = set()
            for ioc in self.iocs.values():
                all_fields.update(ioc.keys())
            
            # Standard field order
            field_order = [
                'value', 'type', 'category', 'hash_type', 'is_private', 'is_suspicious',
                'first_seen', 'last_seen', 'event_count', 'associated_phases'
            ]
            
            # Add any additional fields
            for field in sorted(all_fields):
                if field not in field_order:
                    field_order.append(field)
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=field_order, extrasaction='ignore')
                writer.writeheader()
                
                for ioc in self.iocs.values():
                    # Convert lists to strings for CSV
                    row = ioc.copy()
                    if 'associated_phases' in row and isinstance(row['associated_phases'], list):
                        row['associated_phases'] = ', '.join(row['associated_phases'])
                    writer.writerow(row)
            
            return True
        except Exception as e:
            print(f"Error exporting CSV: {e}")
            return False
    
    def export_by_type(self, output_dir: Path) -> Dict[str, bool]:
        """Export IOCs grouped by type"""
        results = {}
        
        # Group by type
        by_type = {}
        for ioc in self.iocs.values():
            ioc_type = ioc.get('type', 'unknown')
            if ioc_type not in by_type:
                by_type[ioc_type] = {}
            by_type[ioc_type][ioc['value']] = ioc
        
        # Export each type
        for ioc_type, type_iocs in by_type.items():
            exporter = IOCExporter(type_iocs)
            
            json_path = output_dir / f"iocs_{ioc_type}.json"
            csv_path = output_dir / f"iocs_{ioc_type}.csv"
            
            results[f"{ioc_type}_json"] = exporter.export_json(json_path)
            results[f"{ioc_type}_csv"] = exporter.export_csv(csv_path)
        
        return results
    
    def get_summary(self) -> Dict:
        """Get summary of IOCs for export"""
        summary = {
            'total': len(self.iocs),
            'by_type': {},
            'by_phase': {},
            'most_frequent': [],
        }
        
        # Count by type
        for ioc in self.iocs.values():
            ioc_type = ioc.get('type', 'unknown')
            summary['by_type'][ioc_type] = summary['by_type'].get(ioc_type, 0) + 1
        
        # Count by phase
        for ioc in self.iocs.values():
            phases = ioc.get('associated_phases', [])
            if isinstance(phases, str):
                phases = [phases]
            for phase in phases:
                summary['by_phase'][phase] = summary['by_phase'].get(phase, 0) + 1
        
        # Most frequent IOCs
        sorted_iocs = sorted(
            self.iocs.values(),
            key=lambda x: x.get('event_count', 0),
            reverse=True
        )
        summary['most_frequent'] = [
            {
                'value': ioc['value'],
                'type': ioc.get('type', 'unknown'),
                'event_count': ioc.get('event_count', 0),
            }
            for ioc in sorted_iocs[:10]
        ]
        
        return summary
