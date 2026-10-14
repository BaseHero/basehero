const preference = matchMedia("(prefers-color-scheme: dark)");
const apply = () => {
  document.documentElement.dataset.mode = preference.matches ? "dark" : "light";
};
apply();
preference.addEventListener("change", apply);
