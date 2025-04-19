// /var/www/schedule.permadomain.com/html/js/schedule.js
function attachStatusListeners(csrfToken, scheduleId, isReadOnly) {
    console.log('Attaching status listeners');
    document.querySelectorAll('.status-btn').forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const id = this.closest('tr')?.dataset?.id;
            const status = this.dataset.status;
            if (!id || !status) {
                console.error('Invalid row or status');
                alert('Cannot update status: Invalid data.');
                return;
            }
            if (!csrfToken) {
                console.error('CSRF token missing');
                alert('Cannot update status: CSRF token missing.');
                return;
            }
            console.log(`Status button clicked: id=${id}, status=${status}, csrfToken=${csrfToken}`);
            fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: `ajax=1&update_status=1&id=${encodeURIComponent(id)}&status=${encodeURIComponent(status)}&schedule_id=${encodeURIComponent(scheduleId)}&csrf_token=${encodeURIComponent(csrfToken)}`
            })
            .then(response => {
                if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    updateTableAndSummary(data, csrfToken, scheduleId, isReadOnly);
                } else {
                    console.error('Failed to update status: ' + (data.error || 'Unknown error'));
                    alert('Failed to update status: ' + (data.error || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Error updating status:', error);
                alert('Failed to update status: ' + error.message);
            });
        });
    });
}

function attachDeleteListeners(csrfToken, scheduleId, isReadOnly) {
    console.log('Attaching delete listeners');
    document.querySelectorAll('.delete-btn').forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const id = this.closest('tr')?.dataset?.id;
            if (!id) {
                console.error('Invalid row');
                alert('Cannot delete appointment: Invalid data.');
                return;
            }
            if (!csrfToken) {
                console.error('CSRF token missing');
                alert('Cannot delete appointment: CSRF token missing.');
                return;
            }
            if (!confirm('Are you sure you want to delete this appointment?')) {
                return;
            }
            console.log(`Delete button clicked: id=${id}, csrfToken=${csrfToken}`);
            fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: `ajax=1&delete=1&id=${encodeURIComponent(id)}&schedule_id=${encodeURIComponent(scheduleId)}&csrf_token=${encodeURIComponent(csrfToken)}`
            })
            .then(response => {
                if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    updateTableAndSummary(data, csrfToken, scheduleId, isReadOnly);
                } else {
                    console.error('Failed to delete appointment: ' + (data.error || 'Unknown error'));
                    alert('Failed to delete appointment: ' + (data.error || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Error deleting appointment:', error);
                alert('Failed to delete appointment: ' + error.message);
            });
        });
    });
}

function updateTableAndSummary(data, csrfToken, scheduleId, isReadOnly) {
    console.log('Updating table and summary');
    const tbody = document.querySelector('tbody');
    if (!tbody) {
        console.error('Table body not found');
        return;
    }
    tbody.innerHTML = '';
    data.appointments.forEach(appt => {
        const status = appt.status.toLowerCase().trim();
        const bgColor = {
            'scheduled': '#e7f3ff',
            'attended': '#e6ffed',
            'missed': '#ffe6e6',
            'rescheduled': '#fffde7'
        }[status] || '#ffffff';
        const tr = document.createElement('tr');
        tr.dataset.id = appt.id;
        tr.className = `appointment-row status-${status}`;
        tr.style.backgroundColor = bgColor;
        let statusText = status.charAt(0).toUpperCase() + status.slice(1);
        if (['rescheduled', 'missed'].includes(status) && appt.child_display_date) {
            statusText += `<br>${appt.display_date} -> ${appt.child_display_date}`;
        } else if (appt.parent_display_date) {
            statusText += `<br>${appt.parent_display_date} -> ${appt.display_date}`;
        }
        tr.innerHTML = `
            <td>${appt.display_date}</td>
            <td>${statusText}</td>
            ${data.userId && !isReadOnly ? `
                <td>
                    <button class="btn btn-primary btn-sm status-btn" data-status="reschedule">Reschedule</button>
                    <button class="btn btn-success btn-sm status-btn" data-status="attended">Attended</button>
                    <button class="btn btn-danger btn-sm status-btn" data-status="missed">Missed</button>
                    <button class="btn btn-secondary btn-sm status-btn" data-status="scheduled">Reset</button>
                    <button class="btn btn-warning btn-sm delete-btn">Delete</button>
                </td>
            ` : ''}
        `;
        tbody.appendChild(tr);
    });

    const summaryCard = document.querySelector('.summary-card');
    if (summaryCard && data.summary?.start_date) {
        const userId = data.userId || '';
        const username = data.summary.username || 'User';
        const token = data.summary.read_only_token || '';
        const currentUrl = '/schedule.php';
        const fullUrl = `${currentUrl}?token=${encodeURIComponent(token)}`;
        summaryCard.innerHTML = `
            <h5>Appointment Summary for ${username}${userId && !isReadOnly ? '' : ' (Public View)'}</h5>
            <div class="row summary-row g-3">
                <div class="col col-summary">
                    <div class="summary-box">
                        <strong>Start Date</strong>
                        <span>${data.summary.display_start_date || ''}</span>
                    </div>
                </div>
                <div class="col col-summary">
                    <div class="summary-box">
                        <strong>End Date</strong>
                        <span>${data.summary.display_end_date || ''}</span>
                    </div>
                </div>
                <div class="col col-summary">
                    <div class="summary-box">
                        <strong>Total</strong>
                        <span>${data.summary.total || 0}</span>
                    </div>
                </div>
                <div class="col col-summary">
                    <div class="summary-box">
                        <strong>Remaining</strong>
                        <span>${data.summary.remaining || 0}</span>
                    </div>
                </div>
                <div class="col col-summary">
                    <div class="summary-box">
                        <strong>Attended</strong>
                        <span>${data.summary.attended || 0}</span>
                    </div>
                </div>
                <div class="col col-summary">
                    <div class="summary-box">
                        <strong>Missed</strong>
                        <span>${data.summary.missed || 0}</span>
                    </div>
                </div>
                <div class="col col-summary">
                    <div class="summary-box">
                        <strong>Rescheduled</strong>
                        <span>${data.summary.rescheduled || 0}</span>
                    </div>
                </div>
            </div>
            ${userId && !isReadOnly ? `
                <div class="token-section">
                    <div class="token-left">
                        <strong>Read-Only Token:</strong>
                        <a href="${fullUrl}" id="publicUrl">${token}</a>
                    </div>
                    <div class="token-right">
                        <form method="POST" class="d-inline">
                            <input type="hidden" name="csrf_token" value="${csrfToken}">
                            <input type="hidden" name="schedule_id" value="${data.scheduleId || scheduleId}">
                            <button type="submit" name="regenerate_token" class="btn btn-primary btn-sm">Regenerate</button>
                        </form>
                        <button id="copyUrlBtn" class="btn btn-warning btn-sm" data-url="${fullUrl}">Copy URL</button>
                    </div>
                </div>
            ` : ''}
        `;
    }
    attachStatusListeners(csrfToken, scheduleId, isReadOnly);
    attachDeleteListeners(csrfToken, scheduleId, isReadOnly);
    attachCopyUrlListener();
}

function attachCopyUrlListener() {
    console.log('Attaching copy URL listener');
    const copyUrlBtn = document.getElementById('copyUrlBtn');
    if (copyUrlBtn) {
        copyUrlBtn.addEventListener('click', function(e) {
            e.preventDefault();
            const url = this.getAttribute('data-url');
            if (url) {
                navigator.clipboard.writeText(url)
                    .then(() => alert('URL copied to clipboard!'))
                    .catch(err => alert('Failed to copy URL: ' + err.message));
            } else {
                alert('No URL available to copy');
            }
        });
    }
}

function attachScheduleDropdownListener(csrfToken) {
    console.log('Attaching schedule dropdown listener');
    const scheduleSelect = document.getElementById('scheduleSelect');
    if (scheduleSelect) {
        scheduleSelect.addEventListener('change', function(e) {
            const newScheduleId = e.target.value;
            if (!newScheduleId) {
                console.error('No schedule ID selected');
                alert('Please select a valid schedule.');
                return;
            }
            if (!csrfToken) {
                console.error('CSRF token missing');
                alert('Cannot load schedule: CSRF token missing.');
                return;
            }
            console.log(`Schedule dropdown changed: newScheduleId=${newScheduleId}, csrfToken=${csrfToken}`);
            fetch(`/schedule.php?schedule_id=${encodeURIComponent(newScheduleId)}&ajax=1`, {
                method: 'GET',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json'
                }
            })
            .then(response => {
                if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    window.scheduleId = newScheduleId;
                    updateTableAndSummary(data, csrfToken, newScheduleId, window.scheduleIsReadOnly || false);
                    history.pushState({}, '', `/schedule.php?schedule_id=${newScheduleId}`);
                } else {
                    console.error('Failed to load schedule: ' + (data.error || 'Unknown error'));
                    alert('Failed to load schedule: ' + (data.error || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Error loading schedule:', error);
                alert('Failed to load schedule: ' + error.message);
            });
        });
    } else {
        console.warn('Schedule dropdown not found');
    }
}

function initializeSchedule(csrfToken, scheduleId, isReadOnly) {
    console.log(`Initializing schedule: scheduleId=${scheduleId}, isReadOnly=${isReadOnly}, csrfToken=${csrfToken}`);
    if (!csrfToken || !scheduleId) {
        console.error('Missing required configuration');
        alert('Cannot initialize schedule: Missing configuration.');
        return;
    }
    attachStatusListeners(csrfToken, scheduleId, isReadOnly);
    attachDeleteListeners(csrfToken, scheduleId, isReadOnly);
    attachCopyUrlListener();
    // Note: Dropdown listener is handled inline in schedule.php
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded');
    const csrfToken = window.scheduleCsrfToken || '';
    const scheduleId = window.scheduleId || '';
    const isReadOnly = window.scheduleIsReadOnly || false;
    initializeSchedule(csrfToken, scheduleId, isReadOnly);
});
