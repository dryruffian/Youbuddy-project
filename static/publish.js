document.getElementById('publishForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const formData = new FormData(this);
    formData.append('video_id', '{{ video.id }}');

    fetch('{{ url_for("video.publish_video") }}', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Video published successfully');
            window.location.href = '{{ url_for("main.index") }}';
        } else {
            alert('Failed to publish video: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred while publishing the video');
    });
});