'use strict';
// Content is complete without this script; it adds motion and the carousel.
(() => {
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const moving = () => !reduced.matches;
  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, moving() ? ms : 0));
  const whenVisible = (element, run, threshold = 0.2) => {
    if (!('IntersectionObserver' in window)) { run(); return; }
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) { observer.disconnect(); run(); }
    }, { threshold });
    observer.observe(element);
  };

  const header = document.querySelector('.masthead');
  if (header) {
    const update = () => header.classList.toggle('is-scrolled', scrollY > 8);
    addEventListener('scroll', update, { passive: true });
    update();
  }

  document.querySelectorAll('.reveal').forEach((element) => {
    whenVisible(element, () => element.classList.add('is-visible'), 0.1);
  });

  // Opening: the conversation plays out once.
  const steps = [...document.querySelectorAll('[data-seq]')]
    .sort((a, b) => Number(a.dataset.seq) - Number(b.dataset.seq));
  (async () => {
    await wait(350);
    for (const step of steps) {
      step.classList.add('is-shown');
      if ('transient' in step.dataset) {
        await wait(1000);
        step.classList.remove('is-shown');
        continue;
      }
      await wait(Number(step.dataset.delay || 500));
    }
  })();

  // Typing scenes: type each [data-type], then show each [data-after].
  document.querySelectorAll('[data-typing-scene]').forEach((scene) => {
    const typed = [...scene.querySelectorAll('[data-type]')];
    const after = [...scene.querySelectorAll('[data-after]')];
    if (!moving()) { after.forEach((element) => element.classList.add('is-shown')); return; }
    const texts = typed.map((element) => element.textContent);
    typed.forEach((element) => { element.textContent = '\u00a0'; });
    whenVisible(scene, async () => {
      await wait(500);
      for (const [index, element] of typed.entries()) {
        element.textContent = '';
        element.classList.add('is-typing');
        for (const character of texts[index]) { element.textContent += character; await wait(42); }
        element.classList.remove('is-typing');
      }
      for (const element of after) { await wait(450); element.classList.add('is-shown'); }
    }, 0.35);
  });

  // Privacy: a message is encrypted on one phone, unreadable in our cloud, and opened on a laptop.
  const flow = document.querySelector('[data-flow]');
  if (flow) {
    const from = flow.querySelector('[data-flow-from]');
    const cloud = flow.querySelector('[data-flow-cloud]');
    const to = flow.querySelector('[data-flow-to]');
    const toggle = flow.querySelector('.motion-toggle');
    const messages = JSON.parse(flow.dataset.flow);
    const glyphs = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789+/=';
    const scramble = (text) => text.replace(/\S/g, () => glyphs[Math.floor(Math.random() * glyphs.length)]);
    let paused = false;
    let resume = null;
    let playing = false;
    const step = async (ms) => {
      await wait(ms);
      if (paused) await new Promise((resolve) => { resume = resolve; });
    };
    const play = async () => {
      playing = true;
      toggle.textContent = 'Pause';
      for (const message of messages) {
        flow.dataset.stage = 'write';
        from.textContent = message;
        cloud.textContent = '…';
        to.textContent = '…';
        await step(1000);
        flow.dataset.stage = 'up';
        for (let i = 0; i < 7; i += 1) { cloud.textContent = scramble(message); await step(110); }
        flow.dataset.stage = 'down';
        await step(750);
        to.textContent = message;
        flow.dataset.stage = 'read';
        await step(1500);
      }
      playing = false;
      toggle.textContent = 'Play again';
    };
    toggle.addEventListener('click', () => {
      if (!playing) { play(); return; }
      paused = !paused;
      toggle.textContent = paused ? 'Play' : 'Pause';
      if (!paused && resume) { resume(); resume = null; }
    });
    if (moving()) {
      toggle.hidden = false;
      whenVisible(flow, play, 0.45);
    }
  }

  // Use cases: a swipeable carousel with a picker, arrows and keyboard support.
  const carousel = document.querySelector('[data-carousel]');
  if (carousel) {
    const track = carousel.querySelector('.case-track');
    const slides = [...track.querySelectorAll('.case-slide')];
    const pickers = [...carousel.querySelectorAll('[data-go]')];
    const count = carousel.querySelector('[data-count]');
    const picker = carousel.querySelector('.case-picker');
    let current = 0;
    const activate = (index) => {
      current = index;
      slides.forEach((slide, i) => {
        slide.classList.toggle('is-active', i === index);
        slide.inert = i !== index;
      });
      pickers.forEach((picker, i) => picker.setAttribute('aria-current', String(i === index)));
      count.textContent = `${index + 1} / ${slides.length}`;
      picker.scrollTo({ left: Math.max(0, pickers[index].offsetLeft - 22), behavior: moving() ? 'smooth' : 'auto' });
    };
    const go = (index) => {
      const target = (index + slides.length) % slides.length;
      track.scrollTo({ left: slides[target].offsetLeft, behavior: moving() ? 'smooth' : 'auto' });
      activate(target);
    };
    slides.forEach((slide, i) => slide.classList.toggle('is-active', i === 0));
    activate(0);
    pickers.forEach((picker, i) => picker.addEventListener('click', (event) => { event.preventDefault(); go(i); }));
    carousel.querySelector('[data-prev]').addEventListener('click', () => go(current - 1));
    carousel.querySelector('[data-next]').addEventListener('click', () => go(current + 1));
    track.addEventListener('keydown', (event) => {
      if (event.key === 'ArrowRight') { event.preventDefault(); go(current + 1); }
      if (event.key === 'ArrowLeft') { event.preventDefault(); go(current - 1); }
    });
    let settle = null;
    track.addEventListener('scroll', () => {
      clearTimeout(settle);
      settle = setTimeout(() => {
        const index = Math.round(track.scrollLeft / track.clientWidth);
        if (index !== current && slides[index]) activate(index);
      }, 90);
    }, { passive: true });
    // Keep the current slide in place when the width changes, such as unfolding a phone.
    let width = track.clientWidth;
    new ResizeObserver(() => {
      if (track.clientWidth === width) return;
      width = track.clientWidth;
      track.scrollLeft = slides[current].offsetLeft;
    }).observe(track);
  }

})();
