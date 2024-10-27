// static/js/script.js

document.addEventListener('DOMContentLoaded', function () {
    const passwordInput = document.getElementById('password');
    const requirements = {
        length: document.getElementById('length'),
        uppercase: document.getElementById('uppercase'),
        lowercase: document.getElementById('lowercase'),
        number: document.getElementById('number')
    };

    passwordInput.addEventListener('input', function () {
        const password = passwordInput.value;

        // Check for minimum length
        if (password.length >= 8) {
            requirements.length.classList.remove('invalid');
            requirements.length.classList.add('valid');
            requirements.length.querySelector('span').innerHTML = '&#9989;'; // Green checkmark
        } else {
            requirements.length.classList.remove('valid');
            requirements.length.classList.add('invalid');
            requirements.length.querySelector('span').innerHTML = '&#10060;'; // Red cross
        }

        // Check for uppercase letters
        if (/[A-Z]/.test(password)) {
            requirements.uppercase.classList.remove('invalid');
            requirements.uppercase.classList.add('valid');
            requirements.uppercase.querySelector('span').innerHTML = '&#9989;';
        } else {
            requirements.uppercase.classList.remove('valid');
            requirements.uppercase.classList.add('invalid');
            requirements.uppercase.querySelector('span').innerHTML = '&#10060;';
        }

        // Check for lowercase letters
        if (/[a-z]/.test(password)) {
            requirements.lowercase.classList.remove('invalid');
            requirements.lowercase.classList.add('valid');
            requirements.lowercase.querySelector('span').innerHTML = '&#9989;';
        } else {
            requirements.lowercase.classList.remove('valid');
            requirements.lowercase.classList.add('invalid');
            requirements.lowercase.querySelector('span').innerHTML = '&#10060;';
        }

        // Check for numbers
        if (/\d/.test(password)) {
            requirements.number.classList.remove('invalid');
            requirements.number.classList.add('valid');
            requirements.number.querySelector('span').innerHTML = '&#9989;';
        } else {
            requirements.number.classList.remove('valid');
            requirements.number.classList.add('invalid');
            requirements.number.querySelector('span').innerHTML = '&#10060;';
        }
    });
});
