const preference = matchMedia("(prefers-color-scheme: dark)");
const apply = () => {
  document.documentElement.dataset.mode = preference.matches ? "dark" : "light";
};
apply();
preference.addEventListener("change", apply);
// On a Mac the window's own buttons sit inside the location bar.
if (/Mac/.test(navigator.platform) && !/iP(hone|[oa]d)/.test(navigator.platform)) document.documentElement.dataset.platform = "mac";
