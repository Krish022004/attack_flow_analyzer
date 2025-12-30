/**
 * Timeline page JavaScript
 */

let allEvents = [];
let filteredEvents = [];
let currentPage = 1;
const eventsPerPage = 20;

const phaseColors = {
    'reconnaissance': '#FF6B6B',
    'initial_access': '#4ECDC4',
    'lateral_movement': '#45B7D1',
    'exfiltration': '#FFA07A',
    'unknown': '#95A5A6'
};

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

    // Setup table sorting
    AttackFlowUtils.makeTableSortable('events-table');

    // Setup search
    const searchInput = document.getElementById('event-search');
    if (searchInput) {
        searchInput.addEventListener('input', AttackFlowUtils.debounce(() => {
            filterEvents();
        }, 300));
    }

    loadTimeline();
});

async function loadTimeline() {
    try {
        const response = await fetch('/api/timeline');
        const data = await response.json();

        if (data.error) {
            document.getElementById('timeline-chart').innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">
                        <i class="fas fa-chart-line"></i>
                    </div>
                    <div class="empty-state-title">No Timeline Data</div>
                    <div class="empty-state-description">
                        Please upload and analyze logs first to view the timeline.
                    </div>
                    <a href="/upload" class="btn btn-primary mt-3">
                        <i class="fas fa-upload me-2"></i>Upload Logs
                    </a>
                </div>
            `;
            return;
        }

        allEvents = data.events || [];
        filteredEvents = [...allEvents];

        // Show filters and export button
        document.getElementById('filters-card').style.display = 'block';
        document.getElementById('export-btn').style.display = 'block';

        createTimelineVisualization(filteredEvents);
        displayPhaseStatistics(data.phases || {});
        displayTimelineStatistics(data.statistics || {});
        displayEventsTable();
    } catch (error) {
        console.error('Error loading timeline:', error);
        AttackFlowUtils.toast.error('Failed to load timeline data');
    }
}

function createTimelineVisualization(events) {
    if (events.length === 0) {
        document.getElementById('timeline-chart').innerHTML = `
            <div class="alert alert-info">No events to display with current filters.</div>
        `;
        return;
    }

    const timestamps = events.map(e => new Date(e.timestamp));
    const phases = events.map(e => e.phase);
    const colors = phases.map(p => phaseColors[p] || phaseColors['unknown']);

    // Group by phase for better visualization
    const traces = [];
    const phaseOrder = ['reconnaissance', 'initial_access', 'lateral_movement', 'exfiltration', 'unknown'];
    
    phaseOrder.forEach(phase => {
        const phaseEvents = events.filter(e => e.phase === phase);
        if (phaseEvents.length > 0) {
            traces.push({
                x: phaseEvents.map(e => new Date(e.timestamp)),
                y: phaseEvents.map(() => phase),
                mode: 'markers',
                type: 'scatter',
                name: phase.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase()),
                marker: {
                    size: 12,
                    color: phaseColors[phase] || phaseColors['unknown'],
                    line: { width: 2, color: 'white' },
                    opacity: 0.8
                },
                text: phaseEvents.map(e => 
                    `<b>${e.phase}</b><br>` +
                    `Time: ${new Date(e.timestamp).toLocaleString()}<br>` +
                    `IP: ${e.source_ip || 'N/A'}<br>` +
                    `Path: ${(e.path || e.message || 'N/A').substring(0, 50)}`
                ),
                hovertemplate: '%{text}<extra></extra>'
            });
        }
    });

    const layout = {
        title: {
            text: 'Attack Timeline',
            font: { size: 18 }
        },
        xaxis: { 
            title: 'Time',
            type: 'date'
        },
        yaxis: { 
            title: 'Attack Phase',
            categoryorder: 'array',
            categoryarray: phaseOrder.map(p => p.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase()))
        },
        height: 500,
        hovermode: 'closest',
        plot_bgcolor: 'rgba(0,0,0,0)',
        paper_bgcolor: 'rgba(0,0,0,0)',
        legend: {
            orientation: 'h',
            y: -0.2
        },
        margin: { t: 60, r: 20, b: 80, l: 80 }
    };

    Plotly.newPlot('timeline-chart', traces, layout, {responsive: true});
}

function displayPhaseStatistics(phases) {
    const phaseStatsDiv = document.getElementById('phase-stats');
    let phaseStatsHtml = '<ul class="list-group">';
    
    for (const [phase, stats] of Object.entries(phases)) {
        const phaseColor = phaseColors[phase] || phaseColors['unknown'];
        const durationHours = (stats.duration_seconds / 3600).toFixed(2);
        
        phaseStatsHtml += `
            <li class="list-group-item d-flex justify-content-between align-items-center">
                <div>
                    <span class="badge badge-phase-${phase.replace('_', '-')}" style="background-color: ${phaseColor}">
                        ${phase.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                    </span>
                </div>
                <div class="text-end">
                    <span class="badge bg-primary rounded-pill me-2">${stats.count} events</span>
                    <small class="text-muted">${durationHours}h</small>
                </div>
            </li>
        `;
    }
    
    phaseStatsHtml += '</ul>';
    phaseStatsDiv.innerHTML = phaseStatsHtml;
}

function displayTimelineStatistics(stats) {
    const timelineStatsDiv = document.getElementById('timeline-stats');
    timelineStatsDiv.innerHTML = `
        <ul class="list-group">
            <li class="list-group-item d-flex justify-content-between">
                <span><i class="fas fa-list me-2"></i>Total Events:</span>
                <strong>${stats.total_events || 0}</strong>
            </li>
            <li class="list-group-item d-flex justify-content-between">
                <span><i class="fas fa-clock me-2"></i>Duration:</span>
                <strong>${(stats.total_duration_hours || 0).toFixed(2)} hours</strong>
            </li>
            <li class="list-group-item d-flex justify-content-between">
                <span><i class="fas fa-chart-bar me-2"></i>Most Frequent Phase:</span>
                <strong>${stats.most_frequent_phase?.phase?.replace('_', ' ') || 'N/A'}</strong>
            </li>
            <li class="list-group-item d-flex justify-content-between">
                <span><i class="fas fa-hourglass-half me-2"></i>Longest Phase:</span>
                <strong>${stats.longest_phase?.phase?.replace('_', ' ') || 'N/A'}</strong>
            </li>
            <li class="list-group-item d-flex justify-content-between">
                <span><i class="fas fa-exchange-alt me-2"></i>Phase Transitions:</span>
                <strong>${stats.phase_transitions || 0}</strong>
            </li>
        </ul>
    `;
}

function displayEventsTable() {
    const tbody = document.getElementById('events-tbody');
    tbody.innerHTML = '';

    if (filteredEvents.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center text-muted py-4">
                    <i class="fas fa-inbox fa-2x mb-2"></i><br>
                    No events found
                </td>
            </tr>
        `;
        document.getElementById('pagination-container').innerHTML = '';
        return;
    }

    const paginated = AttackFlowUtils.paginate(filteredEvents, currentPage, eventsPerPage);

    paginated.data.forEach((event, index) => {
        const row = tbody.insertRow();
        const phaseColor = phaseColors[event.phase] || phaseColors['unknown'];
        row.innerHTML = `
            <td>${AttackFlowUtils.formatDateTime(event.timestamp)}</td>
            <td>
                <span class="badge" style="background-color: ${phaseColor}">
                    ${event.phase.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                </span>
            </td>
            <td><code>${event.source_ip || '-'}</code></td>
            <td>${(event.path || event.message || '-').substring(0, 50)}${(event.path || event.message || '').length > 50 ? '...' : ''}</td>
            <td>${event.status_code || '-'}</td>
            <td>
                <button class="btn btn-sm btn-outline-primary" onclick="showEventDetails(${paginated.data.indexOf(event)})">
                    <i class="fas fa-eye"></i>
                </button>
            </td>
        `;
    });

    // Pagination
    if (paginated.totalPages > 1) {
        let paginationHtml = '<nav><ul class="pagination justify-content-center">';
        
        // Previous button
        paginationHtml += `
            <li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
                <a class="page-link" href="#" onclick="changePage(${currentPage - 1}); return false;">
                    <i class="fas fa-chevron-left"></i>
                </a>
            </li>
        `;

        // Page numbers
        for (let i = 1; i <= paginated.totalPages; i++) {
            if (i === 1 || i === paginated.totalPages || (i >= currentPage - 2 && i <= currentPage + 2)) {
                paginationHtml += `
                    <li class="page-item ${i === currentPage ? 'active' : ''}">
                        <a class="page-link" href="#" onclick="changePage(${i}); return false;">${i}</a>
                    </li>
                `;
            } else if (i === currentPage - 3 || i === currentPage + 3) {
                paginationHtml += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
            }
        }

        // Next button
        paginationHtml += `
            <li class="page-item ${currentPage === paginated.totalPages ? 'disabled' : ''}">
                <a class="page-link" href="#" onclick="changePage(${currentPage + 1}); return false;">
                    <i class="fas fa-chevron-right"></i>
                </a>
            </li>
        `;

        paginationHtml += '</ul></nav>';
        document.getElementById('pagination-container').innerHTML = paginationHtml;
    } else {
        document.getElementById('pagination-container').innerHTML = '';
    }
}

function changePage(page) {
    currentPage = page;
    displayEventsTable();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function showEventDetails(index) {
    const event = filteredEvents[index];
    if (!event) return;

    const modalBody = document.getElementById('event-modal-body');
    modalBody.innerHTML = `
        <div class="row">
            <div class="col-md-6 mb-3">
                <strong><i class="fas fa-clock me-2"></i>Timestamp:</strong>
                <p>${AttackFlowUtils.formatDateTime(event.timestamp)}</p>
            </div>
            <div class="col-md-6 mb-3">
                <strong><i class="fas fa-project-diagram me-2"></i>Phase:</strong>
                <p>
                    <span class="badge" style="background-color: ${phaseColors[event.phase] || phaseColors['unknown']}">
                        ${event.phase.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                    </span>
                </p>
            </div>
            <div class="col-md-6 mb-3">
                <strong><i class="fas fa-network-wired me-2"></i>Source IP:</strong>
                <p><code>${event.source_ip || 'N/A'}</code></p>
            </div>
            <div class="col-md-6 mb-3">
                <strong><i class="fas fa-check-circle me-2"></i>Status Code:</strong>
                <p>${event.status_code || 'N/A'}</p>
            </div>
            <div class="col-12 mb-3">
                <strong><i class="fas fa-file-alt me-2"></i>Path/Message:</strong>
                <p><code>${event.path || event.message || 'N/A'}</code></p>
            </div>
            <div class="col-12 mb-3">
                <strong><i class="fas fa-tag me-2"></i>Log Type:</strong>
                <p>${event.log_type || 'N/A'}</p>
            </div>
            ${event.confidence ? `
            <div class="col-12 mb-3">
                <strong><i class="fas fa-percentage me-2"></i>Confidence:</strong>
                <p>${(event.confidence * 100).toFixed(1)}%</p>
            </div>
            ` : ''}
        </div>
    `;

    const modal = new bootstrap.Modal(document.getElementById('eventModal'));
    modal.show();
}

function applyFilters() {
    const phaseFilter = document.getElementById('phase-filter').value;
    const ipFilter = document.getElementById('ip-filter').value.toLowerCase();
    const timeRangeFilter = document.getElementById('time-range-filter').value;

    filteredEvents = allEvents.filter(event => {
        // Phase filter
        if (phaseFilter && event.phase !== phaseFilter) {
            return false;
        }

        // IP filter
        if (ipFilter && !(event.source_ip || '').toLowerCase().includes(ipFilter)) {
            return false;
        }

        // Time range filter
        if (timeRangeFilter !== 'all') {
            const eventTime = new Date(event.timestamp);
            const now = new Date();
            let cutoffTime;

            switch (timeRangeFilter) {
                case '1h':
                    cutoffTime = new Date(now - 60 * 60 * 1000);
                    break;
                case '6h':
                    cutoffTime = new Date(now - 6 * 60 * 60 * 1000);
                    break;
                case '24h':
                    cutoffTime = new Date(now - 24 * 60 * 60 * 1000);
                    break;
                case '7d':
                    cutoffTime = new Date(now - 7 * 24 * 60 * 60 * 1000);
                    break;
            }

            if (eventTime < cutoffTime) {
                return false;
            }
        }

        return true;
    });

    currentPage = 1;
    createTimelineVisualization(filteredEvents);
    displayEventsTable();
    AttackFlowUtils.toast.info(`Showing ${filteredEvents.length} of ${allEvents.length} events`);
}

function clearFilters() {
    document.getElementById('phase-filter').value = '';
    document.getElementById('ip-filter').value = '';
    document.getElementById('time-range-filter').value = 'all';
    document.getElementById('event-search').value = '';
    
    filteredEvents = [...allEvents];
    currentPage = 1;
    createTimelineVisualization(filteredEvents);
    displayEventsTable();
}

function filterEvents() {
    const searchTerm = document.getElementById('event-search').value.toLowerCase();
    
    if (!searchTerm) {
        filteredEvents = allEvents;
    } else {
        filteredEvents = allEvents.filter(event => {
            return JSON.stringify(event).toLowerCase().includes(searchTerm);
        });
    }

    currentPage = 1;
    displayEventsTable();
}

function exportTimeline() {
    // Simple export to JSON
    const dataStr = JSON.stringify(filteredEvents, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `timeline-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
    AttackFlowUtils.toast.success('Timeline exported successfully');
}

