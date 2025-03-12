document.addEventListener('DOMContentLoaded', function () {
    // DOM manipulations or animations that use `document`
    const sections = document.querySelectorAll('section');

    const options = {
        root: null,
        threshold: 0.5,
    };

    const observer = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('in-view');
            }
        });
    }, options);

    sections.forEach(section => {
        observer.observe(section);
    });
});
