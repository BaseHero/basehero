'use strict';
// Shared Dispatch modes, no saved preference or remote assets. Query override is
// for design review; otherwise follow system changes on every page.
(() => {
  const requested = new URLSearchParams(location.search).get('mode');
  const system = matchMedia('(prefers-color-scheme: dark)');
  const apply = () => {
    document.documentElement.dataset.mode = ['light', 'dark'].includes(requested)
      ? requested : system.matches ? 'dark' : 'light';
  };
  apply();
  system.addEventListener('change', apply);
})();
