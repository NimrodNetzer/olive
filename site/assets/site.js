// Reveal-on-scroll, animated bars, and copy buttons. No dependencies.
(function () {
  var io = 'IntersectionObserver' in window ? new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (!e.isIntersecting) return;
      e.target.classList.add('in');
      e.target.querySelectorAll('.fill[data-w]').forEach(function (f) { f.style.width = f.dataset.w; });
      io.unobserve(e.target);
    });
  }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' }) : null;

  document.querySelectorAll('.rv').forEach(function (el) {
    if (io) io.observe(el);
    else { el.classList.add('in'); el.querySelectorAll('.fill[data-w]').forEach(function (f) { f.style.width = f.dataset.w; }); }
  });

  document.querySelectorAll('.copy[data-copy]').forEach(function (b) {
    b.addEventListener('click', function () {
      var done = function () { b.textContent = 'copied'; setTimeout(function () { b.textContent = 'copy'; }, 1600); };
      try { navigator.clipboard.writeText(b.dataset.copy).then(done, function () {}); } catch (e) {}
    });
  });
})();
