document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.copy-btn').forEach(button => {
        button.addEventListener('click', () => {
            const text = button.getAttribute('data-text');
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => {
                    const original = button.innerHTML;
                    button.innerHTML = '<i class="fas fa-check"></i> Copied!';
                    setTimeout(() => button.innerHTML = original, 2000);
                }).catch(err => console.error('Copy failed:', err));
            } else {
                console.error('Clipboard API not supported');
            }
        });
    });
});