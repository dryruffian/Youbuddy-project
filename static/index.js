function renameVideo(videoId) {
    const newFilename = document.getElementById(`newFilename${videoId}`).value;
    fetch('/rename_video', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            video_id: videoId,
            new_filename: newFilename
        }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Video renamed successfully');
            location.reload();
        } else {
            alert('Failed to rename video: ' + data.message);
        }
    })
    .catch((error) => {
        console.error('Error:', error);
        alert('An error occurred while renaming the video');
    });
}

function deleteVideo(videoId) {
    fetch('/delete_video', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            video_id: videoId
        }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Video deleted successfully');
            location.reload();
        } else {
            alert('Failed to delete video: ' + data.message);
        }
    })
    .catch((error) => {
        console.error('Error:', error);
        alert('An error occurred while deleting the video');
    });
}