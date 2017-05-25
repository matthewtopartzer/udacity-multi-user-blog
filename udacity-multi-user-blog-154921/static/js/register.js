$(document).ready(function () {
    $('#registerform').validate({
        rules: {
            username: {
                required: true,
                minlenght: 3
            },
            password: {
                required: true,
                minlength: 3
            },
            verify: {
                required: true,
                minlength: 3
            }
        },
        submitHandler: function (form) {
            return true;
        }
    });
});
