import './styles/dispatch/tokens.css';
import './app.css';
import App from './App.svelte';
import { mount, unmount } from 'svelte';

const media = matchMedia('(prefers-color-scheme: dark)');
const setMode = () => { document.documentElement.dataset.mode = media.matches ? 'dark' : 'light'; };
setMode();
media.addEventListener('change', setMode);
const target = document.getElementById('app')!;
let app = mount(App, { target });
// Test an app restart against the same fake backend without using WebView storage.
if (import.meta.env.MODE === 'fake') {
  window.__bhRestart = async () => {
    await unmount(app);
    app = mount(App, { target });
  };
}
