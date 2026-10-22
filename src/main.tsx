import { createRoot } from 'react-dom/client';
import '@fontsource-variable/vazirmatn';
import '@fontsource-variable/jetbrains-mono';
import App from './App.tsx';
import './index.css';

createRoot(
  document.getElementById('root') as HTMLElement
).render(<App />);

/* Hide the critical <style> fallback inside index.html once React mounts. */
const bootFallback = document.getElementById('boot-fallback');
if (bootFallback) {
  bootFallback.classList.add('is-hidden');
  window.setTimeout(() => bootFallback.remove(), 600);
}
