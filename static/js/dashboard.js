/**
 * Dashboard-specific JavaScript
 */

// Update navigation active state
document.addEventListener('DOMContentLoaded', function() {
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });
});

async function loadStatistics() {
    try {
        const response = await fetch('/api/statistics');
        const stats = await response.json();
        
        // Animate numbers
        if (stats.ingestion && stats.ingestion.total_events) {
            const totalEventsEl = document.getElementById('total-events');
            if (totalEventsEl) {
                AttackFlowUtils.animateNumber(totalEventsEl, stats.ingestion.total_events);
            }
        }
        
        if (stats.correlation && stats.correlation.total_groups) {
            const correlationGroupsEl = document.getElementById('correlation-groups');
            if (correlationGroupsEl) {
                AttackFlowUtils.animateNumber(correlationGroupsEl, stats.correlation.total_groups);
            }
        }
        
        if (stats.phases) {
            const phaseCount = Object.keys(stats.phases).length;
            const attackPhasesEl = document.getElementById('attack-phases');
            if (attackPhasesEl) {
                AttackFlowUtils.animateNumber(attackPhasesEl, phaseCount);
            }
        }
        
        if (stats.iocs && stats.iocs.total_iocs) {
            const iocsDetectedEl = document.getElementById('iocs-detected');
            if (iocsDetectedEl) {
                AttackFlowUtils.animateNumber(iocsDetectedEl, stats.iocs.total_iocs);
            }
        }

        // Phase distribution chart
        if (stats.phases) {
            const phases = Object.keys(stats.phases);
            const counts = phases.map(p => stats.phases[p].count || 0);
            
            const phaseColors = {
                'reconnaissance': '#FF6B6B',
                'initial_access': '#4ECDC4',
                'lateral_movement': '#45B7D1',
                'exfiltration': '#FFA07A',
                'unknown': '#95A5A6'
            };
            
            const colors = phases.map(p => phaseColors[p] || phaseColors['unknown']);
            
            // Bar chart
            const barData = [{
                x: phases.map(p => p.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())),
                y: counts,
                type: 'bar',
                marker: {
                    color: colors,
                    line: { width: 1, color: 'white' }
                },
                text: counts,
                textposition: 'auto',
            }];
            
            const barLayout = {
                title: {
                    text: 'Events by Attack Phase',
                    font: { size: 18 }
                },
                xaxis: { 
                    title: 'Phase',
                    tickangle: -45
                },
                yaxis: { title: 'Event Count' },
                plot_bgcolor: 'rgba(0,0,0,0)',
                paper_bgcolor: 'rgba(0,0,0,0)',
                margin: { t: 60, r: 20, b: 80, l: 60 }
            };
            
            Plotly.newPlot('phase-chart', barData, barLayout, {responsive: true});
            
            // Update recent analysis section if there's data
            if (stats.ingestion && stats.ingestion.total_events > 0) {
                const recentAnalysisDiv = document.getElementById('recent-analysis');
                if (recentAnalysisDiv) {
                    recentAnalysisDiv.innerHTML = `
                        <div class="row">
                            <div class="col-md-6">
                                <p><strong>Last Analysis:</strong> ${stats.ingestion.time_range?.start ? AttackFlowUtils.formatDateTime(stats.ingestion.time_range.start) : 'N/A'}</p>
                                <p><strong>Total Events Processed:</strong> ${stats.ingestion.total_events}</p>
                                <p><strong>Log Types:</strong> ${Object.keys(stats.ingestion.log_types || {}).join(', ')}</p>
                            </div>
                            <div class="col-md-6">
                                <p><strong>Duration:</strong> ${stats.ingestion.time_range?.duration_hours ? stats.ingestion.time_range.duration_hours.toFixed(2) + ' hours' : 'N/A'}</p>
                                <p><strong>Phases Detected:</strong> ${Object.keys(stats.phases).length}</p>
                                <p><strong>IOCs Found:</strong> ${stats.iocs?.total_iocs || 0}</p>
                            </div>
                        </div>
                        <div class="mt-3">
                            <a href="/timeline" class="btn btn-primary me-2">
                                <i class="fas fa-timeline me-2"></i>View Timeline
                            </a>
                            <a href="/phases" class="btn btn-outline-primary me-2">
                                <i class="fas fa-project-diagram me-2"></i>View Phases
                            </a>
                            <a href="/iocs" class="btn btn-outline-primary">
                                <i class="fas fa-exclamation-triangle me-2"></i>View IOCs
                            </a>
                        </div>
                    `;
                }
            }
        }
    } catch (error) {
        console.error('Error loading statistics:', error);
        AttackFlowUtils.toast.error('Failed to load statistics');
    }
}

async function generateSamples() {
    try {
        AttackFlowUtils.loadingOverlay.show('Generating sample logs...');
        const response = await fetch('/generate-samples', { method: 'POST' });
        const data = await response.json();
        AttackFlowUtils.loadingOverlay.hide();
        
        if (data.success) {
            AttackFlowUtils.toast.success('Sample logs generated successfully!');
            setTimeout(() => {
                loadStatistics();
            }, 500);
        } else {
            AttackFlowUtils.toast.error('Error generating samples: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        AttackFlowUtils.loadingOverlay.hide();
        AttackFlowUtils.toast.error('Error generating samples: ' + error.message);
    }
}

// Load statistics on page load
loadStatistics();
setInterval(loadStatistics, 10000); // Refresh every 10 seconds

