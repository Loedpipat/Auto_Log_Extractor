document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('uploadForm');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');

    form.addEventListener('submit', function(event) {
        event.preventDefault();
        const formData = new FormData(form);
        const xhr = new XMLHttpRequest();

        xhr.upload.addEventListener('progress', function(e) {
            if (e.lengthComputable) {
                const percentComplete = (e.loaded / e.total) * 100;
                progressBar.style.width = percentComplete + '%';
                progressText.textContent = Math.round(percentComplete) + '%';
            }
        });

        xhr.addEventListener('load', function() {
            if (xhr.status == 200) {
                alert('Upload complete!');
            } else {
                alert('Upload failed!');
            }
        });

        xhr.addEventListener('error', function() {
            alert('Upload failed!');
        });

        xhr.addEventListener('abort', function() {
            alert('Upload aborted!');
        });

        xhr.open('POST', '/upload', true);
        xhr.send(formData);
    });
});