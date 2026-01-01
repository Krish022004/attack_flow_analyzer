/**
 * Upload page JavaScript with drag-and-drop support
 */

let uploadedFiles = [];
let selectedFiles = [];

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

    setupDragAndDrop();
    setupFileInput();
    setupUploadButton();
});

function setupDragAndDrop() {
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('log-files');

    if (!uploadArea || !fileInput) {
        console.error('Upload area or file input not found');
        return;
    }

    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    // Highlight drop area when item is dragged over it
    ['dragenter', 'dragover'].forEach(eventName => {
        uploadArea.addEventListener(eventName, () => {
            uploadArea.classList.add('dragover');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, () => {
            uploadArea.classList.remove('dragover');
        }, false);
    });

    // Handle dropped files
    uploadArea.addEventListener('drop', handleDrop, false);
    uploadArea.addEventListener('click', () => fileInput.click());
}

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    handleFiles(files);
}

function setupFileInput() {
    const fileInput = document.getElementById('log-files');
    if (!fileInput) {
        console.error('File input not found');
        return;
    }
    fileInput.addEventListener('change', (e) => {
        handleFiles(e.target.files);
    });
}

function handleFiles(files) {
    if (!files || files.length === 0) {
        AttackFlowUtils.toast.warning('No files selected');
        return;
    }
    
    selectedFiles = Array.from(files);
    console.log('Selected files:', selectedFiles.map(f => f.name));
    displayFileList();
    document.getElementById('upload-button-container').style.display = 'block';
}

function displayFileList() {
    const fileListDiv = document.getElementById('file-list');
    const fileItemsDiv = document.getElementById('file-items');
    
    if (selectedFiles.length === 0) {
        fileListDiv.style.display = 'none';
        return;
    }

    fileListDiv.style.display = 'block';
    fileItemsDiv.innerHTML = '';

    selectedFiles.forEach((file, index) => {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-upload-item';
        fileItem.innerHTML = `
            <div class="file-info">
                <div class="file-icon">
                    <i class="fas fa-file-alt"></i>
                </div>
                <div class="file-details">
                    <div class="file-name">${file.name}</div>
                    <div class="file-size">${AttackFlowUtils.formatFileSize(file.size)}</div>
                </div>
            </div>
            <div class="file-actions">
                <button class="btn btn-sm btn-outline-danger" onclick="removeFile(${index})">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        fileItemsDiv.appendChild(fileItem);
    });
}

function removeFile(index) {
    selectedFiles.splice(index, 1);
    displayFileList();
    
    if (selectedFiles.length === 0) {
        document.getElementById('upload-button-container').style.display = 'none';
    }
}

function setupUploadButton() {
    const uploadButton = document.getElementById('upload-button');
    if (!uploadButton) {
        console.error('Upload button not found!');
        return;
    }
    
    uploadButton.addEventListener('click', async () => {
        if (selectedFiles.length === 0) {
            AttackFlowUtils.toast.warning('Please select at least one file');
            return;
        }

        const formData = new FormData();
        selectedFiles.forEach((file, index) => {
            if (file && file.name) {
                formData.append('files[]', file, file.name);
                console.log(`Added file ${index + 1}:`, file.name, file.size, 'bytes');
            } else {
                console.warn(`Skipping invalid file at index ${index}`);
            }
        });
        
        console.log('FormData entries:', Array.from(formData.entries()).map(([key, val]) => [key, val instanceof File ? val.name : val]));

        const statusDiv = document.getElementById('upload-status');
        const progressDiv = document.getElementById('upload-progress');
        const progressBar = document.getElementById('upload-progress-bar');
        
        statusDiv.innerHTML = '';
        progressDiv.style.display = 'block';
        progressBar.style.width = '0%';

        // Simulate progress (since we can't track actual upload progress easily)
        let progress = 0;
        const progressInterval = setInterval(() => {
            progress += 10;
            if (progress <= 90) {
                progressBar.style.width = progress + '%';
            }
        }, 200);

        try {
            console.log('Sending upload request...');
            const response = await fetch('/upload', {
                method: 'POST',
                body: formData
            });

            console.log('Response status:', response.status);
            console.log('Response ok:', response.ok);

            clearInterval(progressInterval);
            progressBar.style.width = '100%';

            let data;
            try {
                const responseText = await response.text();
                console.log('Response text:', responseText);
                data = JSON.parse(responseText);
            } catch (e) {
                console.error('Failed to parse response:', e);
                throw new Error('Invalid response from server. Please check server logs.');
            }

            setTimeout(() => {
                progressDiv.style.display = 'none';
                
                if (response.ok) {
                    AttackFlowUtils.toast.success(`Successfully uploaded ${selectedFiles.length} file(s)`);
                    uploadedFiles = data.files || [];
                    if (uploadedFiles.length > 0) {
                        document.getElementById('analyze-card').style.display = 'block';
                        displayUploadedFiles();
                    }
                    
                    // Reset file selection
                    selectedFiles = [];
                    document.getElementById('log-files').value = '';
                    document.getElementById('file-list').style.display = 'none';
                    document.getElementById('upload-button-container').style.display = 'none';
                } else {
                    const errorMsg = data.error || data.message || 'Unknown error';
                    console.error('Upload failed:', errorMsg);
                    AttackFlowUtils.toast.error('Upload failed: ' + errorMsg);
                }
            }, 500);
        } catch (error) {
            clearInterval(progressInterval);
            progressDiv.style.display = 'none';
            console.error('Upload error:', error);
            AttackFlowUtils.toast.error('Upload error: ' + error.message);
        }
    });
}

function displayUploadedFiles() {
    const filesListDiv = document.getElementById('uploaded-files-list');
    filesListDiv.innerHTML = '<h6 class="mb-3"><i class="fas fa-check-circle text-success me-2"></i>Uploaded Files:</h6>';
    
    const listGroup = document.createElement('div');
    listGroup.className = 'list-group';
    
    uploadedFiles.forEach((file, index) => {
        const listItem = document.createElement('div');
        listItem.className = 'list-group-item';
        listItem.innerHTML = `
            <div class="d-flex align-items-center">
                <i class="fas fa-file-alt text-primary me-3"></i>
                <div class="flex-grow-1">
                    <strong>${file.split('/').pop()}</strong>
                </div>
                <i class="fas fa-check-circle text-success"></i>
            </div>
        `;
        listGroup.appendChild(listItem);
    });
    
    filesListDiv.appendChild(listGroup);
}

async function runAnalysis() {
    if (uploadedFiles.length === 0) {
        AttackFlowUtils.toast.warning('Please upload files first');
        return;
    }

    const statusDiv = document.getElementById('analysis-status');
    const progressDiv = document.getElementById('analysis-progress');
    const progressBar = document.getElementById('analysis-progress-bar');
    const progressText = document.getElementById('analysis-progress-text');
    const analyzeButton = document.getElementById('analyze-button');
    
    analyzeButton.disabled = true;
    statusDiv.innerHTML = '';
    progressDiv.style.display = 'block';
    progressBar.style.width = '0%';
    progressText.textContent = 'Analyzing logs...';

    // Simulate progress
    let progress = 0;
    const progressInterval = setInterval(() => {
        progress += 5;
        if (progress <= 95) {
            progressBar.style.width = progress + '%';
            
            if (progress < 30) {
                progressText.textContent = 'Ingesting logs...';
            } else if (progress < 50) {
                progressText.textContent = 'Correlating events...';
            } else if (progress < 70) {
                progressText.textContent = 'Classifying phases...';
            } else if (progress < 90) {
                progressText.textContent = 'Building timeline...';
            } else {
                progressText.textContent = 'Extracting IOCs...';
            }
        }
    }, 300);

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ files: uploadedFiles })
        });

        clearInterval(progressInterval);
        progressBar.style.width = '100%';
        progressText.textContent = 'Analysis complete!';

        const data = await response.json();

        setTimeout(() => {
            progressDiv.style.display = 'none';
            analyzeButton.disabled = false;

            if (response.ok) {
                AttackFlowUtils.toast.success('Analysis completed successfully!');
                statusDiv.innerHTML = `
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle me-2"></i>Analysis completed successfully!
                        <div class="mt-2">
                            <a href="/timeline" class="btn btn-sm btn-outline-success me-2">
                                <i class="fas fa-timeline me-1"></i>View Timeline
                            </a>
                            <a href="/" class="btn btn-sm btn-outline-primary">
                                <i class="fas fa-home me-1"></i>Go to Dashboard
                            </a>
                        </div>
                    </div>
                `;
                setTimeout(() => {
                    window.location.href = '/';
                }, 3000);
            } else {
                AttackFlowUtils.toast.error('Analysis failed: ' + (data.error || 'Unknown error'));
                statusDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
            }
        }, 1000);
    } catch (error) {
        clearInterval(progressInterval);
        progressDiv.style.display = 'none';
        analyzeButton.disabled = false;
        AttackFlowUtils.toast.error('Analysis error: ' + error.message);
        statusDiv.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
    }
}
