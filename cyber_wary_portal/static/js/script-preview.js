$(document).ready(function() {
    $('input[type="checkbox"]').on('change', function() {
        $.post(scriptPreviewURL, $('#scan-components').serialize(), function(data) {
            // Display the returned data in browser
            alert(data)
        });
    });
});