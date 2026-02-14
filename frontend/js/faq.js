'use strict';

document.querySelectorAll('.faq-toggle').forEach(function(btn) {
    btn.addEventListener('click', function() {
        var item = btn.closest('.faq-item');
        var answer = item.querySelector('.faq-answer');
        var chevron = btn.querySelector('.faq-chevron');
        var isOpen = answer.classList.contains('open');

        answer.classList.toggle('open');
        chevron.classList.toggle('open');
        btn.setAttribute('aria-expanded', String(!isOpen));
    });
});
