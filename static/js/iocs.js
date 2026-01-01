/**
 * IOCs page JavaScript
 */

let allIOCs = [];
let filteredIOCs = [];
let currentPage = 1;
const iocsPerPage = 25;

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
    AttackFlowUtils.makeTableSortable('iocs-table');

    // Setup filters
    document.getElementById('type-filter').addEventListener('change', filterIOCs);
    document.getElementById('phase-filter').addEventListener('change', filterIOCs);
    document.getElementById('search').addEventListener('input', AttackFlowUtils.debounce(filterIOCs, 300));

    loadIOCs();
});

async function loadIOCs() {
    try {
        const response = await fetch('/api/iocs');
        const data = await response.json();
        
        if (data.length === 0) {
            document.getElementById('no-iocs').style.display = 'block';
            return;
        }

        allIOCs = data;
        filteredIOCs = [...allIOCs];
        
        updateStatistics();
        displayIOCs();
    } catch (error) {
        console.error('Error loading IOCs:', error);
        AttackFlowUtils.toast.error('Failed to load IOCs');
    }
}

function updateStatistics() {
    const stats = {
        total: allIOCs.length,
        ip: allIOCs.filter(ioc => ioc.type === 'ip').length,
        domain: allIOCs.filter(ioc => ioc.type === 'domain').length,
        hash: allIOCs.filter(ioc => ioc.type === 'hash').length,
        url: allIOCs.filter(ioc => ioc.type === 'url').length,
        user_agent: allIOCs.filter(ioc => ioc.type === 'user_agent').length
    };

    if (stats.total > 0) {
        const statsDiv = document.getElementById('ioc-stats');
        if (statsDiv) {
            statsDiv.style.display = '';
        }
        AttackFlowUtils.animateNumber(document.getElementById('total-iocs'), stats.total);
        AttackFlowUtils.animateNumber(document.getElementById('ip-count'), stats.ip);
        AttackFlowUtils.animateNumber(document.getElementById('domain-count'), stats.domain);
        AttackFlowUtils.animateNumber(document.getElementById('hash-count'), stats.hash);
    }
}

function filterIOCs() {
    const typeFilter = document.getElementById('type-filter').value;
    const phaseFilter = document.getElementById('phase-filter').value;
    const searchTerm = document.getElementById('search').value.toLowerCase();

    filteredIOCs = allIOCs.filter(ioc => {
        if (typeFilter && ioc.type !== typeFilter) return false;
        if (phaseFilter && !(ioc.associated_phases || []).includes(phaseFilter)) return false;
        if (searchTerm && !ioc.value.toLowerCase().includes(searchTerm)) return false;
        return true;
    });

    currentPage = 1;
    displayIOCs();
}

function clearFilters() {
    document.getElementById('type-filter').value = '';
    document.getElementById('phase-filter').value = '';
    document.getElementById('search').value = '';
    filteredIOCs = [...allIOCs];
    currentPage = 1;
    displayIOCs();
}

function displayIOCs() {
    const tbody = document.getElementById('iocs-tbody');
    tbody.innerHTML = '';

    if (filteredIOCs.length === 0) {
        document.getElementById('no-iocs').style.display = 'block';
        document.getElementById('pagination-container').innerHTML = '';
        document.getElementById('showing-count').textContent = '0';
        document.getElementById('total-count').textContent = allIOCs.length;
        return;
    }

    document.getElementById('no-iocs').style.display = 'none';

    const paginated = AttackFlowUtils.paginate(filteredIOCs, currentPage, iocsPerPage);
    document.getElementById('showing-count').textContent = paginated.data.length;
    document.getElementById('total-count').textContent = filteredIOCs.length;

    paginated.data.forEach((ioc, index) => {
        const row = tbody.insertRow();
        
        // Highlight search term
        let valueDisplay = ioc.value;
        const searchTerm = document.getElementById('search').value.toLowerCase();
        if (searchTerm && valueDisplay.toLowerCase().includes(searchTerm)) {
            const regex = new RegExp(`(${searchTerm})`, 'gi');
            valueDisplay = valueDisplay.replace(regex, '<mark>$1</mark>');
        }

        const typeBadgeColors = {
            'ip': 'primary',
            'domain': 'success',
            'hash': 'warning',
            'url': 'info',
            'user_agent': 'danger'
        };

        row.innerHTML = `
            <td><code>${valueDisplay}</code></td>
            <td>
                <span class="badge bg-${typeBadgeColors[ioc.type] || 'secondary'}">
                    ${ioc.type.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                </span>
            </td>
            <td>${ioc.first_seen ? AttackFlowUtils.formatDateTime(ioc.first_seen) : '-'}</td>
            <td>${ioc.last_seen ? AttackFlowUtils.formatDateTime(ioc.last_seen) : '-'}</td>
            <td><span class="badge bg-secondary">${ioc.event_count || 0}</span></td>
            <td>
                ${(ioc.associated_phases || []).map(phase => 
                    `<span class="badge badge-phase-${phase.replace('_', '-')} me-1">${phase.replace('_', ' ')}</span>`
                ).join('') || '-'}
            </td>
            <td>
                <button class="btn btn-sm btn-outline-primary" onclick="showIOCDetails(${paginated.data.indexOf(ioc)})">
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
    displayIOCs();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function showIOCDetails(index) {
    const ioc = filteredIOCs[index];
    if (!ioc) return;

    const modalBody = document.getElementById('ioc-modal-body');
    
    const typeBadgeColors = {
        'ip': 'primary',
        'domain': 'success',
        'hash': 'warning',
        'url': 'info',
        'user_agent': 'danger'
    };

    modalBody.innerHTML = `
        <div class="row">
            <div class="col-md-6 mb-3">
                <strong><i class="fas fa-tag me-2"></i>Type:</strong>
                <p>
                    <span class="badge bg-${typeBadgeColors[ioc.type] || 'secondary'} fs-6">
                        ${ioc.type.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                    </span>
                </p>
            </div>
            <div class="col-md-6 mb-3">
                <strong><i class="fas fa-hashtag me-2"></i>Value:</strong>
                <p><code class="fs-6">${ioc.value}</code></p>
            </div>
            <div class="col-md-6 mb-3">
                <strong><i class="fas fa-calendar-plus me-2"></i>First Seen:</strong>
                <p>${ioc.first_seen ? AttackFlowUtils.formatDateTime(ioc.first_seen) : 'N/A'}</p>
            </div>
            <div class="col-md-6 mb-3">
                <strong><i class="fas fa-calendar-check me-2"></i>Last Seen:</strong>
                <p>${ioc.last_seen ? AttackFlowUtils.formatDateTime(ioc.last_seen) : 'N/A'}</p>
            </div>
            <div class="col-md-6 mb-3">
                <strong><i class="fas fa-list me-2"></i>Event Count:</strong>
                <p><span class="badge bg-secondary fs-6">${ioc.event_count || 0}</span></p>
            </div>
            ${ioc.hash_type ? `
            <div class="col-md-6 mb-3">
                <strong><i class="fas fa-fingerprint me-2"></i>Hash Type:</strong>
                <p><span class="badge bg-warning">${ioc.hash_type.toUpperCase()}</span></p>
            </div>
            ` : ''}
            ${ioc.is_private !== undefined ? `
            <div class="col-md-6 mb-3">
                <strong><i class="fas fa-network-wired me-2"></i>IP Type:</strong>
                <p><span class="badge ${ioc.is_private ? 'bg-info' : 'bg-primary'}">${ioc.is_private ? 'Private' : 'Public'}</span></p>
            </div>
            ` : ''}
            <div class="col-12 mb-3">
                <strong><i class="fas fa-project-diagram me-2"></i>Associated Phases:</strong>
                <p>
                    ${(ioc.associated_phases || []).length > 0 
                        ? (ioc.associated_phases || []).map(phase => 
                            `<span class="badge badge-phase-${phase.replace('_', '-')} me-1">${phase.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}</span>`
                        ).join('')
                        : 'None'
                    }
                </p>
            </div>
            ${ioc.category ? `
            <div class="col-12 mb-3">
                <strong><i class="fas fa-folder me-2"></i>Category:</strong>
                <p>${ioc.category}</p>
            </div>
            ` : ''}
        </div>
    `;

    const modal = new bootstrap.Modal(document.getElementById('iocModal'));
    modal.show();
}

