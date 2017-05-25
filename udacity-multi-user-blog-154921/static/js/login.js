$(document).ready(function () {
    $('#loginform').validate({
        rules: {
            username: {
                required: true,
                minlenght: 3
            },
            password: {
                required: true,
                minlength: 3
            }
        },
        submitHandler: function (form) {
            return true;
        }
    });
});
