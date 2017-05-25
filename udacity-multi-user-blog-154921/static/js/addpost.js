$(document).ready(function () {
    $('#addpostform').validate({
        rules: {
            title: {
                required: true,
                minlenght: 5
            },
            content: {
                required: true,
                minlength: 5
            }
        },
        submitHandler: function (form) { 
            return true; 
        }
    });
});
