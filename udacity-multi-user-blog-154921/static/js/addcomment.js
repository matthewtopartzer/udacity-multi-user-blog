$(document).ready(function () {
    $('#addcommentform').validate({
        rules: {
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
