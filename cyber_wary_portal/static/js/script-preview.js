$(document).ready(function() {
    $('input[name="' + scanTitle + '"]').on('input', function() {
        if ($(this).val()) {
            $('#scan-title').text($(this).val());
            $('#script-scan-title').text($(this).val());
        } else {
            $('#scan-title').text("Untitled Scan");
            $('#script-scan-title').text("Untitled Scan");
        }
    });

    $('.form-dropdown .form-dropdown-menu li').click(function() {
        $(this).parents('.form-dropdown').find('span').text($(this).text());
        $(this).parents('.form-dropdown').find('input').attr('value', $(this).attr('id'));

        if ($(this).attr('id') == "B") {
            $('#scan-type').attr("class", "text-primary");
            $('#scan-type, #script-scan-type').text("Blue Team");
        } else {
            $('#scan-type').attr("class", "text-danger-alt");
            $('#scan-type, #script-scan-type').text("Red Team");
        }

    });

    $('input[name="' + scanMax + '"]').on('input', function() {
        if ($(this).val()) {
            $('#script-scan-max-devices').text($(this).val());
        }
    });


    $('input[name="' + scanExpiry + '"]').on('change', function() {
        if ($(this).val()) {
            $('#script-scan-expiry').text($(this).val());
        }
    });
});